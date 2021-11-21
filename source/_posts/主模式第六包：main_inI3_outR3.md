---
title: 主模式第六包：main_inI3_outR 3
date: 2021-11-20 21:28:38
tags: 
- IPSec
- openswan
- VPN
categories: 
- IPSecVPN
- openswan
---

### 1. 序言

`main_inI3_outR3()`函数是ISAKMP协商过程中==第六包的核心处理函数的入口==，第五六包主要用来验证对方的身份信息，同时此报文也是加密后的报文。这里我们主要说明`main_inI3_outR3`的函数调用关系、处理流程以及对源码的注释分析，关于`main_inI3_outR3`的上下文环境暂不叙述，留给后面的文章进行更新。
<!--more-->
ISAKMP协商报文的处理流程都比较复杂，此函数在协商的报文处理函数中比较复杂的，因此个人学习期间难免有遗漏和理解错误的地方，请大家多多批评指正。

----

目前主要是整理源码中的处理里流程和实现逻辑，尚未深入比较细节的处理；后续在我整理完毕使用主模式协商的9个报文后，我再次结合代码整理每一个报文的详细流程，到时把每一个报文的注意事项、作用，处理方式做一个整体上的把握。同时结合书本上的描述来解释代码层的实现。

-------

第五六个报文的载荷内容如下：

![image-20200605231831766](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205001.png)

### 2.函数调用关系

略。

### 3. 第六个报文流程图

第六个报文的处理流程可以分为三类：

- [x] **解析对方的身份标识(ID)和证书载荷，匹配对方的身份标识**
- [x] **身份验证**
  - [x] 预共享秘钥
  - [x] 数字证书
- [x] **构建应答报文**
  - [x] 身份标识
  - [x] 证书载荷
  - [x] 对数据包进行签名
  - [x] 加密

流程图下图：

![image-20200605232806235](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205004.png)



### 4. main_inI3_outR3_tail源码学习

因为`main_inI3_outR3`中直接调用了`main_inI3_outR3_tail`, 故而直接将`main_inI3_outR3_tail`的源代码进行说明，而不再介绍`main_inI3_outR3`。

该函数的是第六包的核心处理函数，它中调用了`main_id_and_auth()`完成了对方的ID载荷、证书载荷等的解析和认证工作。

在认证成功的前提下，在继续构建自已的应答报文，将自己的身份标识、证书、签名值等载荷封装然后对报文进行加密，最后发送给隧道的发起者。

```c
static stf_status
main_inI3_outR3_tail(struct msg_digest *md
, struct key_continuation *kc)
{
    struct state *const st = md->st;
    u_int8_t auth_payload;
    pb_stream r_id_pbs;	/* ID Payload; also used for hash calculation */
    cert_t mycert;
    bool send_cert;
    unsigned int np;

    /* ID and HASH_I or SIG_I in
     * Note: this may switch the connection being used!
     */
    {
	stf_status r = main_id_and_auth(md, FALSE
					, main_inI3_outR3_continue
					, kc);

	if (r != STF_OK)
	    return r;
    }

    /* send certificate if we have one and auth is RSA */
    mycert = st->st_connection->spd.this.cert;

    send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG
	&& mycert.type != CERT_NONE
	&& ((st->st_connection->spd.this.sendcert == cert_sendifasked
	     && st->hidden_variables.st_got_certrequest)
	    || st->st_connection->spd.this.sendcert==cert_alwayssend);

    doi_log_cert_thinking(md
			  , st->st_oakley.auth
			  , mycert.type
			  , st->st_connection->spd.this.sendcert
			  , st->hidden_variables.st_got_certrequest
			  , send_cert);

    /*************** build output packet HDR*;IDir;HASH/SIG_R ***************/
    /* proccess_packet() would automatically generate the HDR*
     * payload if smc->first_out_payload is not ISAKMP_NEXT_NONE.
     * We don't do this because we wish there to be no partially
     * built output packet if we need to suspend for asynch DNS.
     */
    /* ??? NOTE: this is almost the same as main_inR2_outI3's code */

    /* HDR* out
     * If auth were PKE_AUTH or RPKE_AUTH, ISAKMP_NEXT_HASH would
     * be first payload.
     */
    echo_hdr(md, TRUE, ISAKMP_NEXT_ID);/*回转数据包头;*/

    auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY
	? ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

    /* IDir out *//*添加ID载荷*/
    {
	/* id_hd should be struct isakmp_id, but struct isakmp_ipsec_id
	 * allows build_id_payload() to work for both phases.
	 */
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
		
		id_hd.isaiid_np = (send_cert)? ISAKMP_NEXT_CERT : auth_payload;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &md->rbody, &r_id_pbs)/*添加头部*/
		|| !out_chunk(id_b, &r_id_pbs, "my identity"))/*添加ID内容*/
		    return STF_INTERNAL_ERROR;
		close_output_pbs(&r_id_pbs);
    }

    /* CERT out, if we have one */
    if (send_cert)/*添加证书载荷*/
    {
	pb_stream cert_pbs;

	struct isakmp_cert cert_hd;
	cert_hd.isacert_np = ISAKMP_NEXT_SIG;
	cert_hd.isacert_type = mycert.type;

	openswan_log("I am sending my cert");
	/*添加证书头部描述*/
	if (!out_struct(&cert_hd, &isakmp_ipsec_certificate_desc, &md->rbody, &cert_pbs))
	return STF_INTERNAL_ERROR;
	/*添加证书主体内容*/
	if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&cert_pbs);
    }

#ifdef TPM
    {
	pb_stream *pbs = &md->rbody;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash", st,pbs,sizeof(struct isakmp_hdr),enc_len);

	/* find location of ID PBS */
	tpm_findID(pbs, &r_id_pbs);
    }
#endif

    /* IKEv2 NOTIFY payload */
    np = ISAKMP_NEXT_NONE;
    if(st->st_connection->policy & POLICY_IKEV2_ALLOW) {
	np = ISAKMP_NEXT_VID;
    }

    /* HASH_R or SIG_R out */
    {
	u_char hash_val[MAX_DIGEST_LEN];/*计算ID载荷的hash值*/
	size_t hash_len = main_mode_hash(st, hash_val, FALSE, &r_id_pbs);

	if (auth_payload == ISAKMP_NEXT_HASH)/*如果采用hash进制认证*/
	{
	    /* HASH_R out *//*填充哈希值*/
	    if (!out_generic_raw(np, &isakmp_hash_desc, &md->rbody
	    , hash_val, hash_len, "HASH_R"))
		return STF_INTERNAL_ERROR;
	}
	else/*在哈希的基础上再进行一个签名采用签名进制认证*/
	{
	    /* SIG_R out */
	    u_char sig_val[RSA_MAX_OCTETS];
	    size_t sig_len = RSA_sign_hash(st->st_connection
		, sig_val, hash_val, hash_len);

	    if (sig_len == 0)
	    {
		loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
		return STF_FAIL + AUTHENTICATION_FAILED;
	    }

	    if (!out_generic_raw(np, &isakmp_signature_desc/*填充签名签名信息*/
	    , &md->rbody, sig_val, sig_len, "SIG_R"))
		return STF_INTERNAL_ERROR;
	}
    }

    if(st->st_connection->policy & POLICY_IKEV2_ALLOW) {
	if(!out_vid(ISAKMP_NEXT_NONE, &md->rbody, VID_MISC_IKEv2))
	    return STF_INTERNAL_ERROR;
    }


    /* encrypt message, sans fixed part of header */

    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    /* Last block of Phase 1 (R3), kept for Phase 2 IV generation */
    DBG_cond_dump(DBG_CRYPT, "last encrypted block of Phase 1:"
	, st->st_new_iv, st->st_new_iv_len);
/*保存第一阶段的IV信息*/
    st->st_ph1_iv_len = st->st_new_iv_len;
    set_ph1_iv(st, st->st_new_iv);/*设置初始化向量*/

    /* It seems as per Cisco implementation, XAUTH and MODECFG
     * are not supposed to be performed again during rekey */

    if( st->st_connection->remotepeertype == CISCO &&
	st->st_connection->newest_isakmp_sa != SOS_NOBODY &&
        st->st_connection->spd.this.xauth_client) {
           DBG(DBG_CONTROL, DBG_log("Skipping XAUTH for rekey for Cisco Peer compatibility."));
           st->hidden_variables.st_xauth_client_done = TRUE;
           st->st_oakley.xauth = 0;

           if(st->st_connection->spd.this.modecfg_client) {
                DBG(DBG_CONTROL, DBG_log("Skipping ModeCFG for rekey for Cisco Peer compatibility."));
                st->hidden_variables.st_modecfg_vars_set = TRUE;
                st->hidden_variables.st_modecfg_started = TRUE;
           }
    }

    ISAKMP_SA_established(st->st_connection, st->st_serialno);

    /* ??? If st->st_connectionc->gw_info != NULL,
     * we should keep the public key -- it tested out.
     */

    return STF_OK;
}
```



### 5. oakley_id_and_auth源码学习

`oakley_id_and_auth()`函数的作用是对第五包中的身份标识、证书载荷、证书请求载荷等进行解析，并根据配置的认证方式(**预共享秘钥、数字证书**)完成对对端的认证。

```c
stf_status
oakley_id_and_auth(struct msg_digest *md
		 , bool initiator	/* are we the Initiator? */
		 , bool aggrmode                /* aggressive mode? */
		 , cont_fn_t cont_fn	/* continuation function */
		 , const struct key_continuation *kc	/* current state, can be NULL */
){
    struct state *st = md->st;
    u_char hash_val[MAX_DIGEST_LEN];
    size_t hash_len;
    stf_status r = STF_OK;

    /* if we are already processing a packet on this st, we will be unable
     * to start another crypto operation below */
    if (is_suspended(st)) {/*当前有数据包正在处理*/
        openswan_log("%s: already processing a suspended cyrpto operation "
                     "on this SA, duplicate will be dropped.", __func__);
	return STF_TOOMUCHCRYPTO;
    }
//1 HDR*, IDii, [ CERT, ] SIG_I 
    /* ID Payload in.
     * Note: this may switch the connection being used!
     *//*主动模式时，需要解析对端标识信息;*/
    if (!aggrmode && !decode_peer_id(md, initiator, FALSE))
	return STF_FAIL + INVALID_ID_INFORMATION;
/*对报文进行验签: 
	1.计算对端ID的哈希值
	2. 如果使用的共享秘钥，则报文中使用hash算法进行签名，因此直接比较哈希值是否一致即可
	3. 如果使用证书的方式，则需要使用RSA....等进行验签
*/

    /* Hash the ID Payload.
     * main_mode_hash requires idpl->cur to be at end of payload
     * so we temporarily set if so.
     */
    {
	pb_stream *idpl = &md->chain[ISAKMP_NEXT_ID]->pbs;
	u_int8_t *old_cur = idpl->cur;

	idpl->cur = idpl->roof;
	hash_len = main_mode_hash(st, hash_val, !initiator, idpl);
	idpl->cur = old_cur;
    }

    switch (st->st_oakley.auth)
    {
    case OAKLEY_PRESHARED_KEY:/*共享秘钥认证*/
	{
	    pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs;/*获取哈希载荷的数据部分(即哈希值)*/

	    if (pbs_left(hash_pbs) != hash_len
	    || memcmp(hash_pbs->cur, hash_val, hash_len) != 0)
	    {
		DBG_cond_dump(DBG_CRYPT, "received HASH:"
		    , hash_pbs->cur, pbs_left(hash_pbs));
		loglog(RC_LOG_SERIOUS, "received Hash Payload does not match computed value");
		/* XXX Could send notification back */
		r = STF_FAIL + INVALID_HASH_INFORMATION;
	    }
	}
	break;

    case OAKLEY_RSA_SIG:/*数字证书认证*/
	r = RSA_check_signature(st, hash_val, hash_len
	    , &md->chain[ISAKMP_NEXT_SIG]->pbs
#ifdef USE_KEYRR
	    , kc == NULL? NULL : kc->ac.keys_from_dns
#endif /* USE_KEYRR */
	    , kc == NULL? NULL : kc->ac.gateways_from_dns
	    );

	if (r == STF_SUSPEND)
	{
	    /* initiate/resume asynchronous DNS lookup for key */
	    struct key_continuation *nkc
		= alloc_thing(struct key_continuation, "key continuation");
	    enum key_oppo_step step_done = kc == NULL? kos_null : kc->step;
	    err_t ugh;

	    /* Record that state is used by a suspended md */
	    passert(st->st_suspended_md == NULL);
	    set_suspended(st,md);

	    nkc->failure_ok = FALSE;
	    nkc->md = md;

	    switch (step_done)
	    {
	    case kos_null:
		/* first try: look for the TXT records */
		nkc->step = kos_his_txt;
#ifdef USE_KEYRR
		nkc->failure_ok = TRUE;
#endif
		ugh = start_adns_query(&st->st_connection->spd.that.id
				       , &st->st_connection->spd.that.id	/* SG itself */
				       , ns_t_txt
				       , cont_fn
				       , &nkc->ac);
		break;

#ifdef USE_KEYRR
	    case kos_his_txt:
		/* second try: look for the KEY records */
		nkc->step = kos_his_key;
		ugh = start_adns_query(&st->st_connection->spd.that.id
				       , NULL	/* no sgw for KEY */
				       , ns_t_key
				       , cont_fn
				       , &nkc->ac);
		break;
#endif /* USE_KEYRR */

	    default:
		bad_case(step_done);
	    }

	    if (ugh != NULL)
	    {
		report_key_dns_failure(&st->st_connection->spd.that.id, ugh);
		set_suspended(st, NULL);
		r = STF_FAIL + INVALID_KEY_INFORMATION;
	    } else {
		/*
		 * since this state is waiting for a DNS query, delete
		 * any events that might kill it.
		 */
		delete_event(st);
	    }
	}
	break;

    default:
	bad_case(st->st_oakley.auth);
    }
    if (r == STF_OK)
	DBG(DBG_CRYPT, DBG_log("authentication succeeded"));
    return r;
}
```











