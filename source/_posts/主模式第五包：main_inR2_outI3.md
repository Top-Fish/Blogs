---
title: 主模式第五包：main_inR2_outI3
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

`main_inR2_outI3()`函数是ISAKMP协商过程中==第五包的核心处理函数的入口==，发起端通过此包收到相应端的KE值和Nonce值收到，可以生成需要的密钥信息。这里我们主要说明`main_inR2_outI3`的函数调用关系、处理流程以及对源码的注释分析，关于`main_inR2_outI3`的上下文环境暂不叙述，留给后面的文章进行更新。

ISAKMP协商报文的处理流程都比较复杂，此函数在协商的报文处理函数中比较复杂的，因此个人学习期间难免有遗漏和理解错误的地方，请大家多多批评指正。

对于源码的学习，我并没有把每一行进行备注，而是将自己认为的关键点做了注释或者标注。
<!--more-->

----

目前主要是整理源码中的处理里流程和实现逻辑，尚未深入比较细节的处理；后续在我整理完毕使用主模式协商的9个报文后，我再次结合代码整理每一个报文的详细流程，到时把每一个报文的注意事项、作用，处理方式做一个整体上的把握。同时结合书本上的描述来解释代码层的实现。

-------



### 2.函数调用关系

这里暂时给出xmind整理的思维导图。

![image-20200524090446620](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120204817.png)

### 3. 第五个报文流程图

第五个报文的处理流程主要分为三个大功能：

- [x] **解析收到的对端报文**
  - [x] 密钥交换载荷KE
  - [x] Nonce载荷
- [x] **使用DH算法制作加密密钥、认证密钥、哈希密钥等**
- [x] **构造应答报文（第五个报文）**
  - [x] 签名
  - [x] 报文加密

<img src="F:%5C%E9%9A%8F%E7%AC%94%5Copenswan%5C%E4%B8%BB%E6%A8%A1%E5%BC%8F%E7%AC%AC%E4%BA%94%E5%8C%85%EF%BC%9Amain_inR2_outI3.assets%5Cimage-20200524091648492.png" alt="image-20200524091648492" style="zoom:200%;" />



### 4. main_inR2_outI3（）源码学习

该函数主要的功能是：

- [x] 解析对端的KE载荷和Nonce，因为这是制作密钥的基础材料。
- [x] 解析完毕后，开始制作密钥。

```c
stf_status
main_inR2_outI3(struct msg_digest *md)
{
    struct dh_continuation *dh;
	/*获取受到的第四个报文中的KE载荷*/
    pb_stream *const keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
    struct state *const st = md->st;

    /* if we are already processing a packet on this st, we will be unable
     * to start another crypto operation below */
    if (is_suspended(st)) {
        openswan_log("%s: already processing a suspended cyrpto operation "
                     "on this SA, duplicate will be dropped.", __func__);
	return STF_TOOMUCHCRYPTO;
    }

    /* KE in *//*解析KE载荷并存储在st->st_gr上*/
    RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr"
				 , st->st_oakley.group, keyex_pbs));

    /* Nr in *//*解析Nonce载荷，并存储在st->st_nr*/
    RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_nr, "Nr"));

    dh = alloc_thing(struct dh_continuation, "aggr outR1 DH");
    if(!dh) { return STF_FATAL; }

    dh->md = md;
    set_suspended(st, md);/*挂起当前报文，防止由于耗时操作重新收到对方的重发报文*/
    pcrc_init(&dh->dh_pcrc);
    dh->dh_pcrc.pcrc_func = main_inR2_outI3_cryptotail;
    return start_dh_secretiv(&dh->dh_pcrc, st
			     , st->st_import
			     , INITIATOR
			     , st->st_oakley.group->group);
}
```



### 5. start_dh_secretiv（）源码学习

该函数的主要功能：

- [x] 获取协商的认证算法、哈希算法、oakley群信息
- [x] 准备Nonce、KE、cookie、st_sec_chunk（密钥信息?）
- [x] 制作密钥（该流程中会通过回调函数组装报文并发送）
- [x] 发送完毕报文的后续处理

```c

/*
 * invoke helper to do DH work.
 */
stf_status start_dh_secretiv(struct pluto_crypto_req_cont *cn
			     , struct state *st
			     , enum crypto_importance importance
			     , enum phase1_role init       /* TRUE=g_init,FALSE=g_r */
			     , u_int16_t oakley_group2)
{
    struct pluto_crypto_req r;
    struct pcr_skeyid_q *dhq;
    const chunk_t *pss = get_preshared_secret(st->st_connection);/*获取预共享秘钥*/
    err_t e;
    bool toomuch = FALSE;

    pcr_init(&r, pcr_compute_dh_iv, importance);/*使用DH算法生成三把秘钥*/

    dhq = &r.pcr_d.dhq;

    passert(st->st_sec_in_use);

    /* convert appropriate data to dhq */
    dhq->auth = st->st_oakley.auth;
    dhq->prf_hash = st->st_oakley.prf_hash;
    dhq->oakley_group = oakley_group2;
    dhq->init = init;
    dhq->keysize = st->st_oakley.enckeylen/BITS_PER_BYTE;

    passert(r.pcr_d.dhq.oakley_group != 0);
    DBG(DBG_CONTROL | DBG_CRYPT,
       DBG_log("parent1 type: %d group: %d len: %d\n", r.pcr_type,
	    r.pcr_d.dhq.oakley_group, (int)r.pcr_len));

	/*将*pss的内容拷贝到dhq->space中，起始位置是thespace；同时将dhq->pss指向spce对应的空间。然后更新thespace*/
    if(pss) {
	pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->pss, *pss);
    }
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->ni,  st->st_ni);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->nr,  st->st_nr);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->gi,  st->st_gi);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->gr,  st->st_gr);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space
			   , &dhq->secret, st->st_sec_chunk);

/*最后发起端和相应者Nonce、KE等信息全部拷贝到了space中*/
#ifdef HAVE_LIBNSS
    /*copying required encryption algo*/
    /*dhq->encrypt_algo = st->st_oakley.encrypt;*/
    dhq->encrypter = st->st_oakley.encrypter;
    DBG(DBG_CRYPT, DBG_log("Copying DH pub key pointer to be sent to a thread helper"));
    pluto_crypto_copychunk(&dhq->thespace, dhq->space , &dhq->pubk, st->pubk);
#endif

/*将发起者、相应者cookie也拷贝到dhq->space中*/
    pluto_crypto_allocchunk(&dhq->thespace, &dhq->icookie, COOKIE_SIZE);
    memcpy(wire_chunk_ptr(dhq, &dhq->icookie), st->st_icookie, COOKIE_SIZE);

    pluto_crypto_allocchunk(&dhq->thespace, &dhq->rcookie, COOKIE_SIZE);
    memcpy(wire_chunk_ptr(dhq, &dhq->rcookie)
	   , st->st_rcookie, COOKIE_SIZE);


/*至此，发起端和相应者Nonce、KE、cookie等信息全部拷贝到了space中*/
    passert(dhq->oakley_group != 0);
    e = send_crypto_helper_request(&r, cn, &toomuch);/*r 中包含上述信息，用来生成三把秘钥*/

    if(e != NULL) {
	loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
	if(toomuch) {
	    return STF_TOOMUCHCRYPTO;
	} else {
	    return STF_FAIL;
	}
    } else if(!toomuch) {
	st->st_calculating = TRUE;
	delete_event(st);
	event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);
	return STF_SUSPEND;
    } else {
	/* we must have run the continuation directly, so
	 * complete_state_transition already got called.
	 */
	return STF_INLINE;
    }
}

```



### 6. main_inR2_outI3_cryptotail（）源码学习

```c

static void
main_inR2_outI3_cryptotail(struct pluto_crypto_req_cont *pcrc
			   , struct pluto_crypto_req *r
			   , err_t ugh)
{
  struct dh_continuation *dh = (struct dh_continuation *)pcrc;
  struct msg_digest *md = dh->md;
  struct state *const st = md->st;
  stf_status e;

  DBG(DBG_CONTROLMORE
      , DBG_log("main inR2_outI3: calculated DH, sending R1"));

  if (st == NULL) {
      loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
	      __FUNCTION__);
      if (dh->md)
          release_md(dh->md);
      return;
  }

  passert(cur_state == NULL);
  passert(st != NULL);

  passert(st->st_suspended_md == dh->md);
  set_suspended(st, NULL);	/* no longer connected or suspended */

  set_cur_state(st);
  st->st_calculating = FALSE;

  if(ugh) {
      loglog(RC_LOG_SERIOUS, "failed in DH exponentiation: %s", ugh);
      e = STF_FATAL;
  } else {
      e = main_inR2_outI3_continue(md, r);
  }

  if(dh->md != NULL) {
      complete_v1_state_transition(&dh->md, e);
      if(dh->md) release_md(dh->md);
  }
  reset_cur_state();
}
```



### 7. main_inR2_outI3_cryptotail（）源码学习

该函数的主要功能是：

- [x] 将制作的密钥存储在状态上
- [x] 解析对方报文中的证书，确定是否需要发送证书载荷
- [x] 构造ID标识载荷、并计算哈希
- [x] 如果使用哈希认证则填充哈希载荷；如果使用签名认证则进行数字签名
- [x] 报文加密

```c

/* STATE_MAIN_I2:
 * SMF_PSK_AUTH: HDR, KE, Nr --> HDR*, IDi1, HASH_I
 * SMF_DS_AUTH: HDR, KE, Nr --> HDR*, IDi1, [ CERT, ] SIG_I
 *
 * The following are not yet implemented.
 * SMF_PKE_AUTH: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 *	    --> HDR*, HASH_I
 * SMF_RPKE_AUTH: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 *	    --> HDR*, HASH_I
 */
static stf_status
main_inR2_outI3_continue(struct msg_digest *md
			 , struct pluto_crypto_req *r)
{
    struct state *const st = md->st;
	/*选择认证的载荷类型:哈希\签名*/
    int auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY
	? ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;
    pb_stream id_pbs;	/* ID Payload; also used for hash calculation */
    bool send_cert = FALSE;
    bool send_cr = FALSE;
    generalName_t *requested_ca = NULL;
    cert_t mycert = st->st_connection->spd.this.cert;/*获取自己的证书*/

    finish_dh_secretiv(st, r);/*将DH产生的三把秘钥存储在结构体上*/
    if(!r->pcr_success) {
        return STF_FAIL + INVALID_KEY_INFORMATION;
    }

    /* decode certificate requests */
    decode_cr(md, &requested_ca);/*解析报文中的证书载荷，并使用requested_ca链起来*/

    if(requested_ca != NULL)
    {
	st->hidden_variables.st_got_certrequest = TRUE;
    }

    /*
     * send certificate if we have one and auth is RSA, and we were
     * told we can send one if asked, and we were asked, or we were told
     * to always send one.
     * 同时满足下面的条件再发送证书载荷:
     *		1. 使用RSA签名
     *		2. 本端导入了数字证书
     *		3. 配置要求发送证书或强制发送证书
     *		4. 从对端收到了证书
     */
    send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG
	&& mycert.type != CERT_NONE
	&& ((st->st_connection->spd.this.sendcert == cert_sendifasked
	     && st->hidden_variables.st_got_certrequest)
	    || st->st_connection->spd.this.sendcert==cert_alwayssend
	    || st->st_connection->spd.this.sendcert==cert_forcedtype);

    doi_log_cert_thinking(md
			  , st->st_oakley.auth
			  , mycert.type
			  , st->st_connection->spd.this.sendcert
			  , st->hidden_variables.st_got_certrequest
			  , send_cert);

    /* send certificate request, if we don't have a preloaded RSA public key */
    send_cr = !no_cr_send && send_cert && !has_preloaded_public_key(st);/*是否可以发送证书*/

    DBG(DBG_CONTROL
	, DBG_log(" I am %ssending a certificate request"
		  , send_cr ? "" : "not "));

    /*
     * free collected certificate requests since as initiator
     * we don't heed them anyway
     */
    free_generalNames(requested_ca, TRUE);

    /* done parsing; initialize crypto  */

#ifdef NAT_TRAVERSAL
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD) {
      nat_traversal_natd_lookup(md);/*检测隧道两端是否经过NAT穿越*/
    }
    if (st->hidden_variables.st_nat_traversal) {
      nat_traversal_show_result(st->hidden_variables.st_nat_traversal
				, md->sender_port);
    }
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA) {
      nat_traversal_new_ka_event();
    }
#endif

    /*************** build output packet HDR*;IDii;HASH/SIG_I ***************/
    /* ??? NOTE: this is almost the same as main_inI3_outR3's code */

    /* HDR* out done */
	/*HDR在哪里完成填充的呢???*/
	
    /* IDii out */
    {
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;

	/*从状态/连接上获取本端标识信息*/
	build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
	id_hd.isaiid_np = (send_cert)? ISAKMP_NEXT_CERT : auth_payload;
	if (!out_struct(&id_hd
			, &isakmp_ipsec_identification_desc
			, &md->rbody
			, &id_pbs)
	    || !out_chunk(id_b, &id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&id_pbs);
    }

    /* CERT out */
    if (send_cert)
    {
	pb_stream cert_pbs;

	struct isakmp_cert cert_hd;
	cert_hd.isacert_np = (send_cr)? ISAKMP_NEXT_CR : ISAKMP_NEXT_SIG;
	cert_hd.isacert_type = mycert.type;

	openswan_log("I am sending my cert");

	if (!out_struct(&cert_hd
			, &isakmp_ipsec_certificate_desc
			, &md->rbody
			, &cert_pbs))
	    return STF_INTERNAL_ERROR;

	if(mycert.forced) {
	  if (!out_chunk(mycert.u.blob, &cert_pbs, "forced CERT"))
	    return STF_INTERNAL_ERROR;
	} else {
	  if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
	    return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&cert_pbs);
    }

    /* CR out *//*添加证书请求载荷,即要求对对端进行发送证书以求认证...*/
    if (send_cr)
    {
	openswan_log("I am sending a certificate request");
	if (!build_and_ship_CR(mycert.type
			       , st->st_connection->spd.that.ca
			       , &md->rbody, ISAKMP_NEXT_SIG))
	    return STF_INTERNAL_ERROR;
    }

#ifdef TPM
    {
	pb_stream *pbs = &md->rbody;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash", st,pbs,sizeof(struct isakmp_hdr),enc_len);

	/* find location of ID PBS */
	tpm_findID(pbs, &id_pbs);
    }
#endif

    /* HASH_I or SIG_I out */
    {
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len = main_mode_hash(st, hash_val, TRUE, &id_pbs);

	if (auth_payload == ISAKMP_NEXT_HASH)
	{
	    /* HASH_I out */
	    if (!out_generic_raw(ISAKMP_NEXT_NONE
				 , &isakmp_hash_desc
				 , &md->rbody
				 , hash_val, hash_len, "HASH_I"))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    /* SIG_I out */
	    u_char sig_val[RSA_MAX_OCTETS];
	    size_t sig_len = RSA_sign_hash(st->st_connection
		, sig_val, hash_val, hash_len);

	    if (sig_len == 0)
	    {
		loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
		return STF_FAIL + AUTHENTICATION_FAILED;
	    }

	    if (!out_generic_raw(ISAKMP_NEXT_NONE
				 , &isakmp_signature_desc
				 , &md->rbody
				 , sig_val
				 , sig_len
				 , "SIG_I"))
		return STF_INTERNAL_ERROR;
	}
    }

    /* encrypt message, except for fixed part of header */

    /* st_new_iv was computed by generate_skeyids_iv */
    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    return STF_OK;
}
```







