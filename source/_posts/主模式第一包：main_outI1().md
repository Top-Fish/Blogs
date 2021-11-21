---
title: 主模式第一包：main_outI1()
date: 2021-11-20 21:28:38
tags: 
- IPSec
- openswan
- VPN
categories: 
- IPSecVPN
- openswan
---

## 1. 序言

`main_outI1()`作为主模式主动发起连接请求的核心处理函数，我们可以通过学习该函数的处理流程来探究openswan中报文封装的基本思想。如果之前没有学习基本的函数接口(如in_struct, out_struct, out_sa等)，那么直接学习`main_outI1()`流程是比较困难的。如果想快速学习这几个函数接口，可以查看我先前的文章，我把需要的基本知识、思想等做了基本介绍，看完那几个接口再来学习此后的ISAKMP协商流程会容易很多，起到事半功倍的效果。
<!--more-->
ISAKMP协商报文的处理流程都比较复杂，一个函数有几百行都是很常见的，因此个人学习期间难免有遗漏和理解错误的地方，请大家多多批评指正。

## 2. main_outI1()流程图

下面两个流程图中主要描述了三个函数的处理流程，后面我会分别附上这三个函数的源码信息。

![main_outI1](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120204802.png)

![out_sa处理流程](F:%5C%E9%9A%8F%E7%AC%94%5Copenswan%5C%E4%B8%BB%E6%A8%A1%E5%BC%8F%E7%AC%AC%E4%B8%80%E5%8C%85%EF%BC%9Amain_outI1().assets%5Cimage-20200520000233483.png)

## 3. main_outI1()源码注释

```c
stf_status
main_outI1(int whack_sock
	   , struct connection *c
	   , struct state *predecessor
           , so_serial_t  *newstateno
	   , lset_t policy
	   , unsigned long try
	   , enum crypto_importance importance
	   , struct xfrm_user_sec_ctx_ike * uctx
	   )
{
    struct state *st = new_state();/*创建一个新的状态*/
    struct msg_digest md;   /* use reply/rbody found inside */

    int numvidtosend = 1;  /* we always send DPD VID */
#ifdef NAT_TRAVERSAL
    if (nat_traversal_enabled) {
	numvidtosend++;
    }
#endif
#if SEND_PLUTO_VID || defined(openpgp_peer)
    numvidtosend++;
#endif
#ifdef XAUTH
    if(c->spd.this.xauth_client || c->spd.this.xauth_server) {
	numvidtosend++;
    }
#endif
/*统计VID个数*/
    /* set up new state *//*根据对端IP地址信息生成一个新的cookie*/
    get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);

   /*初始化新的state结构*/
    initialize_new_state(st, c, policy, try, whack_sock, importance);
	
    if(newstateno) *newstateno = st->st_serialno;

    /* IKE version numbers -- used mostly in logging */
    st->st_ike_maj        = IKEv1_MAJOR_VERSION;
    st->st_ike_min        = IKEv1_MINOR_VERSION;

    change_state(st, STATE_MAIN_I1);/*设置当前的状态为STATE_MAIN_I1*/

    if (HAS_IPSEC_POLICY(policy))
	add_pending(dup_any(whack_sock), st, c, policy, 1
	    , predecessor == NULL? SOS_NOBODY : predecessor->st_serialno
	    , uctx
                    );

#ifdef HAVE_LABELED_IPSEC
    /*For main modes states, sec ctx is always null*/
    st->sec_ctx = NULL;
#endif

    if (predecessor == NULL)
	openswan_log("initiating Main Mode");
    else
	openswan_log("initiating Main Mode to replace #%lu", predecessor->st_serialno);

    /* set up reply */
    zero(reply_buffer);/*初始化应答报文(发送的报文)的结构*/
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out */
    {/*添加isakmp头部信息*/
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_SA;
	hdr.isa_xchg = ISAKMP_XCHG_IDPROT;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	/* R-cookie, flags and MessageID are left zero */
	/*长度字段最后设置: close_output_pbs(&reply_stream);*/
	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream, &md.rbody))
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

    /* SA out */
    {/************封装SA载荷**************/
	u_char *sa_start = md.rbody.cur;
	int    policy_index = POLICY_ISAKMP(policy
					    , c->spd.this.xauth_server
					    , c->spd.this.xauth_client);

	/* if we  have an OpenPGP certificate we assume an
	 * OpenPGP peer and have to send the Vendor ID
	 */
	 /*如果存在VID，则需要设置下一载荷的值*/
	int np = numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if (!out_sa(&md.rbody
		    , &oakley_sadb[policy_index], st, TRUE, FALSE, np))
	{
	    openswan_log("outsa fail");
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
	/* save initiator SA for later HASH */
	passert(st->st_p1isa.ptr == NULL);	/* no leak!  (MUST be first time) */
	clonetochunk(st->st_p1isa, sa_start, md.rbody.cur - sa_start
	    , "sa in main_outI1");
    }

    if (SEND_PLUTO_VID || c->spd.this.cert.type == CERT_PGP)
    {
	char *vendorid = (c->spd.this.cert.type == CERT_PGP) ?
	    pgp_vendorid : pluto_vendorid;
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

	if (!out_generic_raw(np, &isakmp_vendor_id_desc, &md.rbody
			     , vendorid, strlen(vendorid), "Vendor ID"))
	    return STF_INTERNAL_ERROR;
    }

    /* Send DPD VID */
    {
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if(!out_vid(np, &md.rbody, VID_MISC_DPD)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT, DBG_log("nat traversal enabled: %d"
			  , nat_traversal_enabled));
    if (nat_traversal_enabled) {
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

	/* Add supported NAT-Traversal VID */
	if (!nat_traversal_insert_vid(np, &md.rbody, st)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }
#endif

#ifdef XAUTH
    if(c->spd.this.xauth_client || c->spd.this.xauth_server) {
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if(!out_vid(np, &md.rbody, VID_MISC_XAUTH)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }
#endif

#ifdef DEBUG
    /* if we are not 0 then something went very wrong above */
    if(numvidtosend != 0) {
	openswan_log("payload alignment problem please check the code in main_inR1_outR2 (num=%d)", numvidtosend);
    }
#endif

    close_message(&md.rbody);
    close_output_pbs(&reply_stream);

    /* let TCL hack it before we mark the length and copy it */
    TCLCALLOUT("avoidEmitting", st, st->st_connection, &md);
    clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
	, "reply packet for main_outI1");

    /* Transmit */
    send_packet(st, "main_outI1", TRUE);

    /* Set up a retransmission event, half a minute henceforth */
    TCLCALLOUT("adjustTimers", st, st->st_connection, &md);

#ifdef TPM
 tpm_stolen:
 tpm_ignore:
#endif
    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    if (predecessor != NULL)
    {
	update_pending(predecessor, st);
	whack_log(RC_NEW_STATE + STATE_MAIN_I1
	    , "%s: initiate, replacing #%lu"
	    , enum_name(&state_names, st->st_state)
	    , predecessor->st_serialno);
    }
    else
    {
	whack_log(RC_NEW_STATE + STATE_MAIN_I1
	    , "%s: initiate", enum_name(&state_names, st->st_state));
    }
    reset_cur_state();
    return STF_OK;
}
```

## 4. out_sa()源码注释

略。此函数400多行，由于流程图上比较详细就不再列出。



### 5. oakley_alg_makedb()源码注释

```c
/*
 * 	Create an OAKLEY proposal based on alg_info and policy
 *
 * Note: maxtrans is an enum, not a count
 * 	Should probably be declared an enum at some point.
 * 	-1 - ???
 * 	 0 - No limit
 * 	 1 - One proposal - period
 * 	 2 - One DH group, take first DH group and ignore any that don't match
 *根据配置的秘钥算法信息重新生成一个sadb信息
 *传入的sadb应该为固定的秘钥算法信息，因此需要根据策略来重新生成一个新的sadb
 */
struct db_sa *
oakley_alg_makedb(struct alg_info_ike *ai
		  , struct db_sa *base
		  , int maxtrans)
{
    /* struct db_context inprog UNUSED; */
    struct db_sa *gsp = NULL;
    struct db_sa *emp_sp = NULL;
    struct ike_info *ike_info;
    unsigned ealg, halg, modp, eklen=0;
    /* Next two are for multiple proposals in agressive mode... */
    unsigned last_modp=0, wrong_modp=0;
    struct encrypt_desc *enc_desc;
    int transcnt = 0;
    int i;

    /*
     * start by copying the proposal that would have been picked by
     * standard defaults.
     */

    if (!ai) {
	DBG(DBG_CRYPT,DBG_log("no IKE algorithms for this connection "));

	return NULL;
    }

    gsp = NULL;

    /*
     * for each group, we will create a new proposal item, and then
     * append it to the list of transforms in the conjoint point.
     *
     * when creating each item, we will use the first transform
     * from the base item as the template.
     */
    ALG_INFO_IKE_FOREACH(ai, ike_info, i) {//遍历策略中的算法信息

	if(ike_info->ike_default == FALSE) {
	    struct db_attr  *enc, *hash, *auth, *grp, *enc_keylen, *new_auth;
	    struct db_trans *trans;
	    struct db_prop  *prop;
	    struct db_prop_conj *cprop;

		/*获取到加密算法、哈希算法、认证算法、加密秘钥长度等信息*/
	    ealg = ike_info->ike_ealg;
	    halg = ike_info->ike_halg;
	    modp = ike_info->ike_modp;
	    eklen= ike_info->ike_eklen;
		
#if 1  /*判断这几个算法是否合法、是否存在等*/
	    if (!ike_alg_enc_present(ealg)) {
		DBG_log("oakley_alg_makedb() "
			"ike enc ealg=%d not present",
			ealg);
		continue;
	    }
	    if (!ike_alg_hash_present(halg)) {
		DBG_log("oakley_alg_makedb() "
			"ike hash halg=%d not present",
			halg);
		continue;
	    }
	    enc_desc = ike_alg_get_encrypter(ealg);

	    passert(enc_desc != NULL);
	    if (eklen	/*秘钥长度是否符合要求*/
		&& (eklen < enc_desc->keyminlen
		    || eklen >  enc_desc->keymaxlen))

		{
		    DBG_log("ike_alg_db_new() "
			    "ealg=%d (specified) keylen:%d, "
			    "not valid "
			    "min=%d, max=%d"
			    , ealg
			    , eklen
			    , enc_desc->keyminlen
			    , enc_desc->keymaxlen
			    );
		    continue;
		}
#endif
	    /* okay copy the basic item, and modify it. */
	    if(eklen > 0)
	    {
		emp_sp = sa_copy_sa(&oakley_empty, 0);/*重新分配一个新的描述信息*/
		cprop = &base->prop_conjs[0];/*从定义的描述信息中获取参数*/
		prop = &cprop->props[0];/*建议载荷*/
		trans = &prop->trans[0];/*变换载荷*/
		new_auth = &trans->attrs[2];/*属性载荷*/

		cprop = &emp_sp->prop_conjs[0];
		prop = &cprop->props[0];
		trans = &prop->trans[0];
		auth = &trans->attrs[2];
		*auth = *new_auth;		/*给新的描述结构中设置认证算法*/
	    }
	    else
		emp_sp = sa_copy_sa_first(base);

	    passert(emp_sp->prop_conj_cnt == 1);
	    cprop = &emp_sp->prop_conjs[0];

	    passert(cprop->prop_cnt == 1);
	    prop = &cprop->props[0];

	    passert(prop->trans_cnt == 1);
	    trans = &prop->trans[0];

	    passert(trans->attr_cnt == 4 || trans->attr_cnt == 5);
	    enc  = &trans->attrs[0]; /*加密*/
	    hash = &trans->attrs[1];/*哈希*/
	    auth = &trans->attrs[2];/*认证*/
	    grp  = &trans->attrs[3];/*DH组?*/

	    if(eklen > 0) {
		enc_keylen = &trans->attrs[4];
		enc_keylen->val = eklen;/*设置加密算法长度*/
	    } else
		trans->attr_cnt = 4;

	    passert(enc->type.oakley == OAKLEY_ENCRYPTION_ALGORITHM);
	    if(ealg > 0) {
		enc->val = ealg;/*设置加密算法*/
	    }

	    modp = ike_info->ike_modp;
	    eklen= ike_info->ike_eklen;

	    passert(hash->type.oakley == OAKLEY_HASH_ALGORITHM);
	    if(halg > 0) {
		hash->val = halg;/*设置哈希算法*/
	    }

	    passert(auth->type.oakley == OAKLEY_AUTHENTICATION_METHOD);
	    /* no setting for auth type for IKE */

	    passert(grp->type.oakley  == OAKLEY_GROUP_DESCRIPTION);
	    if(modp > 0) {
		grp->val = modp;  /*设置认证算法*/
	    }
	} else {
	    emp_sp = sa_copy_sa(base, 0);
	}

	if(maxtrans == 1) {/*最大变换载荷数*/
            /*
             *  We're going to leave maxtrans == 1 alone in case there
             * really really is a case where we only want 1.
             */

	    if(transcnt == 0) {
		DBG(DBG_CONTROL, DBG_log("using transform (%d,%d,%d,%ld)"
					 , ike_info->ike_ealg
					 , ike_info->ike_halg
					 , ike_info->ike_modp
					 , (long)ike_info->ike_eklen));
		if(gsp) {
		    free_sa(gsp);
		}
		gsp = emp_sp;
	    } else {
		free_sa(emp_sp);
	    }

	    if(transcnt > 0) {
		if(transcnt == 1) {
		    loglog(RC_LOG_SERIOUS

			   , "multiple transforms were set in aggressive mode. Only first one used.");
		}

		loglog(RC_LOG_SERIOUS
		       , "transform (%d,%d,%d,%ld) ignored."
		       , ike_info->ike_ealg
		       , ike_info->ike_halg
		       , ike_info->ike_modp
		       , (long)ike_info->ike_eklen);
	    }

	} else {
            /*
             * Now...  We're allowing multiple proposals...  Are we allowing
             * multiple DH groups?
             */

	    struct db_sa *new;

            if(maxtrans == 2 && transcnt > 0 && ike_info->ike_modp != last_modp ) {
                /* Not good.
                 * Already got a DH group and this one doesn't match */
		if(wrong_modp == 0) {
		    loglog(RC_LOG_SERIOUS
			   , "multiple DH groups were set in aggressive mode. Only first one used.");
		}

		loglog(RC_LOG_SERIOUS
		           , "transform (%d,%d,%d,%ld) ignored."
		           , ike_info->ike_ealg
		           , ike_info->ike_halg
		           , ike_info->ike_modp
		           , (long)ike_info->ike_eklen);

                wrong_modp++;

		free_sa(emp_sp);
	    } else if(gsp) {
	    /* now merge emp_sa and gsp */
		new = sa_merge_proposals(gsp, emp_sp);/*变换载荷合并*/
		free_sa(gsp);
		free_sa(emp_sp);
		emp_sp = NULL;
		gsp = new;
	    } else {
		gsp = emp_sp;
	    }
            last_modp = ike_info->ike_modp;
	}
	transcnt++;
    }
    gsp->parentSA = TRUE;

    return gsp;
}
```

