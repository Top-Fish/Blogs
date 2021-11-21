---
title: 快速模式第三包之quick_inR1_outI2()
date: 2021-11-20 21:28:38
tags: 
- IPSec
- openswan
- VPN
categories: 
- IPSecVPN
- openswan
---
![image-20200909232524545](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205850.png)


<!--more-->
### 1. 序言

在上一篇中博客中长话短说了第二包的处理流程，前两个报文的交互是快速模式的关键交互，用来协商会话参数(加解密算法、会话秘钥等)，而第三包则是对前两个报文的认证，流程上简单了很多 。`quick_inR1_outI2()`处理流程实现的功能如下：

- [x] **解析SA载荷**(对端选择的加解密算法信息)、**KE载荷**(pfs)、**Nonce载荷**。
- [x] 构造第三个报文
- [x] **生成密钥生成材料keymats**
- [x] **建立完整的IPsec SA**
  - [x] 发起端建立的为完整IPSec SA,包括入SA和出SA，响应端有所不同。
- [x] **启动DPD检测**



### 2. quick_inR1_outI2()的处理流程

第三个报文的完整处理流程如下：

![image-20200913094835778](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205853.png)





### 3. 快速模式第③包报文格式

 该报文中的杂凑载荷是对前面交换的认证。第③包仅有ISAKMP头部和杂凑载荷构成，杂凑载荷的消息摘要是以==一个0字节的MsgID、去掉载荷头的发起者Nonce以及去掉了载荷头的响应者Nonce==为输入参数生成的，计算公式如下：
$$
HASH(3) = PRF(SKEY-a,  0|MsgID|Ni_b|Nr_b)
$$


![图片1](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205858.png)



### 4. quick_inR1_outI2()源码分析

接口`quick_inR1_outI2()`的主要功能如下：

- [x] ==验证报文的完整性==
- [x] ==解析响应端选择的SA载荷==
  - [x] **加解密算法(ESP协议、AH协议，...)**
  - [x] **认证算法**
  - [x] **封装模式（隧道模式 ？传输模式）**
- [x] ==解析Nonce载荷==
- [x] 如果启用PFS
  - [ ] 解析KE载荷
  - [ ] 再次计算DH交换值

```c
stf_status
quick_inR1_outI2(struct msg_digest *md)
{
    struct state *const st = md->st;

    /* HASH(2) in *//*验证报文的哈希载荷*/
    CHECK_QUICK_HASH(md
	, quick_mode_hash12(hash_val, hash_pbs->roof, md->message_pbs.roof
	    , st, &st->st_msgid, TRUE)
	, "HASH(2)", "Quick R1");

    /* SA in */
    {
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];

	/*解析对端选择的SA载荷*/
	RETURN_STF_FAILURE(parse_ipsec_sa_body(&sa_pd->pbs
	    , &sa_pd->payload.sa, NULL, TRUE, st));
    }

    /* Nr in *//*解析对端Nonce载荷*/
    RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_nr, "Nr"));

    /* [ KE ] in (for PFS) *//*根据配置策略解析对端KE载荷*/
    RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gr, "Gr", "Quick Mode R1"));

    if(st->st_pfs_group) {/*如果支持PFS功能，则需要进行DH算法计算*/
		struct dh_continuation *dh = alloc_thing(struct dh_continuation
							 , "quick outI2 DH");

		/* set up DH calculation */
		dh->md = md;
		passert(st != NULL);
		set_suspended(st, md);
		pcrc_init(&dh->dh_pcrc);
		dh->dh_pcrc.pcrc_func = quick_inR1_outI2_continue;
		return start_dh_secret(&dh->dh_pcrc, st
				       , st->st_import
				       , INITIATOR
				       , st->st_pfs_group->group);
    } else {
		/* just call the tail function */
		struct dh_continuation dh;

		dh.md=md;
		return quick_inR1_outI2_cryptotail(&dh, NULL);
    }
}
```



### 4. quick_inR1_outI2_cryptotail()源码分析

接口`quick_inR1_outI2_cryptotail()`的主要功能如下：

- [x] ==检验ID载荷收发是否一致==

  这里是通过ID载荷来协商IPSec隧道的保护子网信息

- [x] NAT-T相关处理

- [x] 构造应答报文

- [x] ==计算keymats值==

- [x] ==建立IPSecSA==

- [x] ==初始化本隧道的DPD定时器==

```c
stf_status
quick_inR1_outI2_cryptotail(struct dh_continuation *dh
			    , struct pluto_crypto_req *r)
{
    struct msg_digest *md = dh->md;
    struct state *st = md->st;
    struct connection *c = st->st_connection;

    if (st->st_pfs_group != NULL && r!=NULL) {
	finish_dh_secret(st, r);/*获取密钥信息*/
        if(!r->pcr_success) {
            return STF_FAIL + INVALID_KEY_INFORMATION;
        }
    }

#ifdef NAT_TRAVERSAL
    ... ...
#endif

    /* [ IDci, IDcr ] in; these must match what we sent */

    {
	struct payload_digest *const IDci = md->chain[ISAKMP_NEXT_ID];
	struct payload_digest *IDcr;

	if (IDci != NULL)/*应答报文中包含ID载荷*/
	{
	    /* ??? we are assuming IPSEC_DOI */

	    /* IDci (we are initiator) *//*确定收发ID载荷是否一致*/
	    if (!check_net_id(&IDci->payload.ipsec_id, &IDci->pbs
			      , &st->st_myuserprotoid, &st->st_myuserport
			      , &st->st_connection->spd.this
                              , &st->st_localaddr
			      , "our client"))
		return STF_FAIL + INVALID_ID_INFORMATION;

	    /* we checked elsewhere that we got two of them */
	    IDcr = IDci->next;/*响应端ID载荷是否匹配*/
	    passert(IDcr != NULL);

	    /* IDcr (responder is peer) */

	    if (!check_net_id(&IDcr->payload.ipsec_id, &IDcr->pbs
			      , &st->st_peeruserprotoid, &st->st_peeruserport
			      , &st->st_connection->spd.that
                              , &st->st_remoteaddr
			      , "peer client"))
		return STF_FAIL + INVALID_ID_INFORMATION;

	    /*
	     * if there is a NATOA payload, then use it as
	     *    &st->st_connection->spd.that.client, if the type
	     * of the ID was FQDN
	     */
#ifdef NAT_TRAVERSAL
	... ...
#endif

	}
	else
	{
	    /* no IDci, IDcr: we must check that the defaults match our proposal */
	    if (!subnetisaddr(&c->spd.this.client, &c->spd.this.host_addr)/*两个地址一样即可*/
		|| !subnetisaddr(&c->spd.that.client, &c->spd.that.host_addr))
	    {
		loglog(RC_LOG_SERIOUS, "IDci, IDcr payloads missing in message"
		    " but default does not match proposal");
		return STF_FAIL + INVALID_ID_INFORMATION;
	    }
	}
    }

    /**************** build reply packet HDR*, HASH(3) ****************/

    /* HDR* out done ISAKMP头部已经填充完毕*/

    /* HASH(3) out -- sometimes, we add more content */
    {
	u_char	/* set by START_HASH_PAYLOAD: */
	    *r_hashval,	/* where in reply to jam hash value */
	    *r_hash_start;      /* start of what is to be hashed */

	/*填充hash载荷*/
	START_HASH_PAYLOAD(md->rbody, ISAKMP_NEXT_NONE);

	/*计算哈希载荷值，用于对端检测报文的完整性*/
	(void)quick_mode_hash3(r_hashval, st);
        r_hash_start = r_hash_start;   /* otherwise complaint about never used */
    }

   /* Derive new keying material *//*计算密钥生成材料*/
    compute_keymats(st);

    /* Tell the kernel to establish the inbound, outbound, and routing part
     * of the new SA (unless the commit bit is set -- which we don't support).
     * We do this before any state updating so that
     * failure won't look like success.
     */
    if (!install_ipsec_sa(md->pst, st, TRUE))/*建立IPsecSA*/
	return STF_INTERNAL_ERROR;

    /* encrypt message, except for fixed part of header */
	/*加密*/
    if (!encrypt_message(&md->rbody, st))
    {
        delete_ipsec_sa(st, FALSE);
        return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */
    }

    st->st_connection->newest_ipsec_sa = st->st_serialno;

    /* note (presumed) success */
    if (c->gw_info != NULL)
	c->gw_info->key->last_worked_time = now();

    /* If we have dpd delay and dpdtimeout set, then we are doing DPD
	on this conn, so initialize it */
    if (st->st_connection->dpd_delay && st->st_connection->dpd_timeout) {
        if(dpd_init(st) != STF_OK) {/*启动DPD定时器*/
            delete_ipsec_sa(st, FALSE);
            return STF_FAIL;
        }
    }

    return STF_OK;
}
```



### 4. compute_keymats()源码分析

`compute_keymats()`是一个很重的函数，功能是第二阶段计算生成密钥材料，它的计算方式如下：

- [x] 如果启用PFS功能：

$$
KEYMATS = PRF(SKEYSTR-d, g^{xy} | protocol | SPI | Ni-b |Nr-b   )
$$

- [x] 未用PFS功能：

$$
KEYMATS = PRF(SKEYSTR-d, protocol | SPI | Ni-b |Nr-b   )
$$

需要注意的是：

- $g^{xy}$是第二阶段通过额外的DH交换计算得到的(==DH计算出的共享秘钥==)，存储在`st->st_shared`中。此变量虽然在第一阶段时也有生成，但是第二阶段使用了第一阶段复制的state状态，并未使用第一阶段中的`st_shared`的值，因此第二阶段的`st->st_shared`只有在进行额外的DH交换后才会生成，且不会使用第一阶段的共享密钥的值。



```c
static void
compute_keymats(struct state *st)
{
    if (st->st_ah.present)
	compute_proto_keymat(st, PROTO_IPSEC_AH, &st->st_ah, "AH");
    if (st->st_esp.present)
	compute_proto_keymat(st, PROTO_IPSEC_ESP, &st->st_esp, "ESP");
}

/*
 * Produce the new key material of Quick Mode.
 * RFC 2409 "IKE" section 5.5
 * specifies how this is to be done.
 *###############################################
 *	compute_proto_keymat非常重要的密钥协商函数
 *###############################################
 */
 
static void
compute_proto_keymat(struct state *st
		     , u_int8_t protoid
		     , struct ipsec_proto_info *pi
		     , const char *satypename)
{
    size_t needed_len = 0; /* bytes of keying material needed */

    /* Add up the requirements for keying material
     * (It probably doesn't matter if we produce too much!)
     */
    switch (protoid)
    {
    case PROTO_IPSEC_ESP:
	    switch (pi->attrs.transattrs.encrypt)/*加密算法*/
	    {
	    	    case ESP_NULL:
			needed_len = 0;
			break;
		    case ESP_DES:
			needed_len = DES_CBC_BLOCK_SIZE;
			break;
		    case ESP_3DES:
			needed_len = DES_CBC_BLOCK_SIZE * 3;
			break;
		    case ESP_AES:
			needed_len = AES_CBC_BLOCK_SIZE;
			/* if an attribute is set, then use that! */
			if(st->st_esp.attrs.transattrs.enckeylen) {/*如果属性载荷设置了此参数，则使用此参数的值*/
			    needed_len = st->st_esp.attrs.transattrs.enckeylen/8;
			}
			break;

		    default:
#ifdef KERNEL_ALG
			if((needed_len=kernel_alg_esp_enc_keylen(pi->attrs.transattrs.encrypt))>0) {
				/* XXX: check key_len "coupling with kernel.c's */
				if (pi->attrs.transattrs.enckeylen) {
					needed_len=pi->attrs.transattrs.enckeylen/8;
					DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
							"key_len=%d from peer",
							(int)needed_len));
				}
				break;
			}
#endif
			bad_case(pi->attrs.transattrs.encrypt);
	    }
	    DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
				     "needed_len (after ESP enc)=%d",
				     (int)needed_len));

	    switch (pi->attrs.transattrs.integ_hash)/*哈希算法*/
	    {
		    case AUTH_ALGORITHM_NONE:
			break;
		    case AUTH_ALGORITHM_HMAC_MD5:
			needed_len += HMAC_MD5_KEY_LEN;
			break;
		    case AUTH_ALGORITHM_HMAC_SHA1:
			needed_len += HMAC_SHA1_KEY_LEN;
			break;
		    default:
#ifdef KERNEL_ALG
		      if (kernel_alg_esp_auth_ok(pi->attrs.transattrs.integ_hash, NULL) == NULL) {
			  needed_len += kernel_alg_esp_auth_keylen(pi->attrs.transattrs.integ_hash);
			  break;
		      }
#endif
		    case AUTH_ALGORITHM_DES_MAC:
			bad_case(pi->attrs.transattrs.integ_hash);
			break;

	    }
	    DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
				    "needed_len (after ESP auth)=%d",
				    (int)needed_len));
	    break;

    case PROTO_IPSEC_AH:
	    switch (pi->attrs.transattrs.encrypt)
	    {
		    case AH_MD5:
			needed_len = HMAC_MD5_KEY_LEN;
			break;
		    case AH_SHA:
			needed_len = HMAC_SHA1_KEY_LEN;
			break;
		    default:
#ifdef KERNEL_ALG
			if (kernel_alg_ah_auth_ok(pi->attrs.transattrs.integ_hash, NULL)) {
			    needed_len += kernel_alg_ah_auth_keylen(pi->attrs.transattrs.integ_hash);
			    break;
			}
#endif
			bad_case(pi->attrs.transattrs.encrypt);
	    }
	    break;

    default:
	bad_case(protoid);
    }

/*将所有算法需要的密钥长度全部相加，从而生成所需长度的密钥材料*/

    pi->keymat_len = needed_len;

    /* Allocate space for the keying material.
     * Although only needed_len bytes are desired, we
     * must round up to a multiple of ctx.hmac_digest_len
     * so that our buffer isn't overrun.
     */
    {
	struct hmac_ctx ctx_me, ctx_peer;
	size_t needed_space;	/* space needed for keying material (rounded up) */
	size_t i;

	hmac_init_chunk(&ctx_me, st->st_oakley.prf_hasher, st->st_skeyid_d);

	ctx_peer = ctx_me;	/* duplicate initial conditions */
	needed_space = needed_len + pad_up(needed_len, ctx_me.hmac_digest_len);
	replace(pi->our_keymat, alloc_bytes(needed_space, "keymat in compute_keymat()"));
	replace(pi->peer_keymat, alloc_bytes(needed_space, "peer_keymat in quick_inI1_outR1()"));

/*
* 准备计算秘钥所需的所有材料
*	1. DH交换生成的共享秘钥
*	2. 协议protocol
*	3. SPI
*	4. Ni_b
*	5. Nr_b
*/
	for (i = 0;; )
	{
        /*1. DH交换生成的共享秘钥*/
	    if (st->st_shared.ptr != NULL)
	    {
            /* PFS: include the g^xy */
            hmac_update_chunk(&ctx_me, st->st_shared);
            hmac_update_chunk(&ctx_peer, st->st_shared);
	    }
        /*2. 协议protocol*/
	    hmac_update(&ctx_me, &protoid, sizeof(protoid));
	    hmac_update(&ctx_peer, &protoid, sizeof(protoid));
		/*3. SPI*/
	    hmac_update(&ctx_me, (u_char *)&pi->our_spi, sizeof(pi->our_spi));
	    hmac_update(&ctx_peer, (u_char *)&pi->attrs.spi, sizeof(pi->attrs.spi));
		/*4. Ni_b*/
	    hmac_update_chunk(&ctx_me, st->st_ni);
	    hmac_update_chunk(&ctx_peer, st->st_ni);
		/*5. Nr_b*/
	    hmac_update_chunk(&ctx_me, st->st_nr);
	    hmac_update_chunk(&ctx_peer, st->st_nr);

	    hmac_final(pi->our_keymat + i, &ctx_me);
	    hmac_final(pi->peer_keymat + i, &ctx_peer);

	    i += ctx_me.hmac_digest_len;
	    if (i >= needed_space)
		break;

	    /* more keying material needed: prepare to go around again */
	    hmac_reinit(&ctx_me);
	    hmac_reinit(&ctx_peer);

	    hmac_update(&ctx_me, pi->our_keymat + i - ctx_me.hmac_digest_len, ctx_me.hmac_digest_len);
	    hmac_update(&ctx_peer, pi->peer_keymat + i - ctx_peer.hmac_digest_len, ctx_peer.hmac_digest_len);
	}
    }
/*双方能计算出对端的密钥材料信息???*/
    DBG(DBG_CRYPT,
	DBG_log("%s KEYMAT\n",satypename);
	DBG_dump("  KEYMAT computed:\n", pi->our_keymat, pi->keymat_len);
	DBG_dump("  Peer KEYMAT computed:\n", pi->peer_keymat, pi->keymat_len));
}

```



### 5. dpd_init()源码分析

DPD功能对应有两个事件：

- [ ] **EVENT_DPD_TIMEOUT**

  第一阶段的定时器，在第二阶段已经断开的情况下，用来检测第一阶段是否超时

- [ ] **DPD_EVENT**

  第二阶段的定时器，长时间未通讯时断开连接，并启动第一阶段的定时器

这个定时器机制实际使用时会复杂一点。可以参考注释说明。

```c
/**
 * Initialize RFC 3706 Dead Peer Detection
 *
 * @param st An initialized state structure
 * @return void
 *
 * How DPD works.
 *
 * There are two kinds of events that can be scheduled.
 * At most one of them is schedule at any given time.
 *
 * The EVENT_DPD_TIMEOUT event, if it ever goes off, means that
 * neither the ISAKMP SA nor the IPsec SA has *RECEIVED* any DPD
 * events lately.
 *
 * 0) So, every time we receive a DPD (R_U_THERE or R_U_ACK), then
 *    we delete any DPD event (EVENT_DPD or EVENT_DPD_TIMEOUT), and
 *    we schedule a new DPD_EVENT (sending) for "delay" in the future.
 *
 * 1) When the DPD_EVENT goes off, we check the phase 2 (if there is one)
 *    SA to see if there was incoming traffic. If there was, then we are happy,
 *    we set a new DPD_EVENT, and we are done.
 *
 * 2) If there was no phase 2 activity, we check if there was a recent enough
 *    DPD activity (st->st_last_dpd). If so, we just reschedule, and do
 *    nothing.
 *
 * 3) Otherwise, we send a DPD R_U_THERE message, and set the
 *    EVENT_DPD_TIMEOUT on the phase 1.
 *
 * One thing to realize when looking at "ipsec whack --listevents" output,
 * is there there will only be DPD_EVENT_TIMEOUT events if there are
 * outstanding R_U_THERE messages.
 *
 * The above is the basic idea, but things are a bit more complicated because
 * multiple phase 2s can share the same phase 1 ISAKMP SA. Each phase 2 state
 * has its own DPD_EVENT. Further, we start a DPD_EVENT for phase 1 when it
 * gets established. This is because the phase 2 may never actually succeed
 * (usually due to authorization issues, which may be DNS or otherwise related)
 * and if the responding end dies (gets restarted, or the conn gets reloaded
 * with the right policy), then we may have a bum phase 1 SA, and we can not
 * re-negotiate. (This happens WAY too often)
 *
 * The phase 2 dpd_init() will attempt to kill the phase 1 DPD_EVENT, if it
 * can, to reduce the amount of work.
 *
 * The st_last_dpd member which is used is always the one from the phase 1.
 * So, if there are multiple phase 2s, then if any of them receive DPD data
 * they will update the st_last_dpd, so the test in #2 will avoid the traffic
 * for all by one phase 2.
 *
 * Note that the EVENT_DPD are attached to phase 2s (typically), while the
 * EVENT_DPD_TIMEOUT are attached to phase 1s only.
 *
 * Finally, if the connection is using NAT-T, then we ignore the phase 2
 * activity check, because in the case of a unidirectional stream (VoIP for
 * a conference call, for instance), we may not send enough traffic to keep
 * the NAT port mapping valid.
 *
 */

stf_status
dpd_init(struct state *st)
{
    /**
     * Used to store the 1st state
     */
#ifdef HAVE_LABELED_IPSEC
	if(st->st_connection->loopback) {
            openswan_log("dpd is not required for ipsec connections over loopback");
            return STF_OK;
	}
#endif
    struct state *p1st;

    /* find the related Phase 1 state */
    p1st = find_state_ikev1(st->st_icookie, st->st_rcookie,
		      &st->st_connection->spd.that.host_addr, 0);/*第一阶段的msgid为0*/

    if (p1st == NULL) {
        loglog(RC_LOG_SERIOUS, "could not find phase 1 state for DPD");

	/*
	 * if the phase 1 state has gone away, it really should have
	 * deleted all of its children.
	 * Why would this happen? because a quick mode SA can take
	 * some time to create (DNS lookups for instance), and the phase 1
	 * might have been taken down for some reason in the meantime.
	 * We really can not do anything here --- attempting to invoke
	 * the DPD action would be a good idea, but we really should
	 * do that outside this function.
	 */
	return STF_FAIL;
    }

    /* if it was enabled, and we haven't turned it on already */
    if (p1st->hidden_variables.st_dpd) {
	time_t n = now();
	openswan_log("Dead Peer Detection (RFC 3706): enabled");

	if(st->st_dpd_event == NULL || (st->st_connection->dpd_delay + n) < st->st_dpd_event->ev_time) {
	    delete_dpd_event(st);
	    event_schedule(EVENT_DPD, st->st_connection->dpd_delay, st);
	}

    } else {
      openswan_log("Dead Peer Detection (RFC 3706): not enabled because peer did not advertise it");
    }

    if(p1st != st) {/*第一阶段的DPD_EVENT事件已经没有必要，可以进行删除了，第二阶段会有自己的DPD_EVENT*/
	/* st was not a phase 1 SA, so kill the DPD_EVENT on the phase 1 */
	if(p1st->st_dpd_event != NULL
	   && p1st->st_dpd_event->ev_type == EVENT_DPD) {
	    delete_dpd_event(p1st);
	}
    }
    return STF_OK;
}
```

### 6. install_ipsec_sa()源码分析

略。![img](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205907.jpg)