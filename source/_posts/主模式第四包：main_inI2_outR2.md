---
title: 主模式第四包：main_inI2_outR2
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

`main_inI2_outR2()`函数是ISAKMP协商过程中==第四包的核心处理函数的入口==，同时在此处理流程中已经获取到足够的隧道信息，可以生成需要的密钥信息。这里我们主要说明`main_inI2_outR2`的函数调用关系、处理流程以及对源码的注释分析，关于`main_inI2_outR2`的上下文环境暂不叙述，留给后面的文章进行更新。
<!--more-->
ISAKMP协商报文的处理流程都比较复杂，此函数在协商的报文处理函数中比较复杂的，因此个人学习期间难免有遗漏和理解错误的地方，请大家多多批评指正。

对于源码的学习，我并没有把每一行进行备注，而是将自己认为的关键点做了注释或者标注。



### 2.函数调用关系

暂略。(此流程调用比较多，后面会在补充上)



### 3. 第四个报文流程图

第四个报文处理流程大致可以划分为四类功能：

- [x] 解析收到的第三个报文内容
- [x] 生成随机数(本段的KE和Nonce值)
- [x] 构造应答报文
- [x] 使用DH算法制作秘钥(三把钥匙)

整理的处理流程如下：

![image-20200522000821053](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120204827.png)

个人觉得这个流程做的还是很清晰和准确的(原谅我没有上色)![img]()

![img](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120204834.gif)



### 4. main_inI2_outR2源码分析

```c

stf_status
main_inI2_outR2(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;

    /* if we are already processing a packet on this st, we will be unable
     * to start another crypto operation below */
    if (is_suspended(st)) {/*为了方式该流程处理时间过长导致对端超时重发*/
        openswan_log("%s: already processing a suspended cyrpto operation "
                     "on this SA, duplicate will be dropped.", __func__);
	return STF_TOOMUCHCRYPTO;
    }

    /* KE in *//*从报文中获取KE载荷，并填充到st->st_gi上*/
    RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi"
				 , st->st_oakley.group, keyex_pbs));

    /* Ni in *//*从报文中获取Nonce载荷，并填充到st->st_ni上*/
    RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_ni, "Ni"));

    /* decode certificate requests *//*解析证书载荷，以链表的方式存储在st->st_connection->requested_ca*/
    ikev1_decode_cr(md, &st->st_connection->ikev1_requested_ca_names);

    if(st->st_connection->requested_ca != NULL)
    {
	st->hidden_variables.st_got_certrequest = TRUE;
    }


#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT
	, DBG_log("inI2: checking NAT-T: %d and %d"
		  , nat_traversal_enabled
		  , st->hidden_variables.st_nat_traversal));

    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD) {
       DBG(DBG_NATT, DBG_log(" NAT_T_WITH_NATD detected"));
       nat_traversal_natd_lookup(md);/*根据哈希值确定是否经过NAT;状态上的NAT-T标志在此处做的修改*/
    }
    if (st->hidden_variables.st_nat_traversal) {/*打印NAT-T、端口浮动相关信息*/
       nat_traversal_show_result(st->hidden_variables.st_nat_traversal
				 , md->sender_port);
    }
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA) {
       DBG(DBG_NATT, DBG_log(" NAT_T_WITH_KA detected"));
       nat_traversal_new_ka_event();/*添加NAT-T的保活事件*/
    }
#endif

    {
	struct ke_continuation *ke = alloc_thing(struct ke_continuation
					     , "inI2_outR2 KE");

	ke->md = md;
	set_suspended(st, md);

	passert(st->st_sec_in_use == FALSE);
	pcrc_init(&ke->ke_pcrc);
	ke->ke_pcrc.pcrc_func = main_inI2_outR2_continue;
	return build_ke(&ke->ke_pcrc, st
			, st->st_oakley.group, st->st_import);
    }
}
```



### 5. nat_traversal_natd_lookup源码分析

```c

/*检查是否需要经过NAT-T*/
void nat_traversal_natd_lookup(struct msg_digest *md)
{
	unsigned char hash_me[MAX_DIGEST_LEN];
	unsigned char hash_him[MAX_DIGEST_LEN];
	struct payload_digest *p;
	struct state *st = md->st;
	bool found_me = FALSE;
	bool found_him= FALSE;
	int i;

	passert(st);
	passert(md->iface);
	passert(st->st_oakley.prf_hasher);

	/** Count NAT-D **/
	for (p = md->chain[ISAKMP_NEXT_NATD_RFC], i=0;
	     p != NULL;
	     p = p->next, i++);/*统计NAT-D的数量*/

	/**
	 * We need at least 2 NAT-D (1 for us, many for peer)
	 */
	if (i < 2) {
		loglog(RC_LOG_SERIOUS,
		"NAT-Traversal: Only %d NAT-D - Aborting NAT-Traversal negotiation", i);
		st->hidden_variables.st_nat_traversal = 0;
		return;
	}

	/**
	 * First one with my IP & port
	 */
	_natd_hash(st->st_oakley.prf_hasher, hash_me
		   , st->st_icookie, st->st_rcookie
		   , &(md->iface->ip_addr)
		   , ntohs(md->iface->port));

	/**
	 * The others with sender IP & port
	 */
	_natd_hash(st->st_oakley.prf_hasher, hash_him
		   , st->st_icookie, st->st_rcookie
		   , &(md->sender), ntohs(md->sender_port));

	for (p = md->chain[ISAKMP_NEXT_NATD_RFC], i=0;
	     p != NULL && (!found_me || !found_him);
	     p = p->next)
	  {
	    DBG(DBG_NATT,
		DBG_log("NAT_TRAVERSAL hash=%d (me:%d) (him:%d)"
			, i, found_me, found_him);
		DBG_dump("expected NAT-D(me):", hash_me,
			 st->st_oakley.prf_hasher->hash_digest_len);
		DBG_dump("expected NAT-D(him):", hash_him,
			 st->st_oakley.prf_hasher->hash_digest_len);
		DBG_dump("received NAT-D:", p->pbs.cur, pbs_left(&p->pbs));
		);

	    if ( (pbs_left(&p->pbs) == st->st_oakley.prf_hasher->hash_digest_len)
		 && (memcmp(p->pbs.cur, hash_me
			    , st->st_oakley.prf_hasher->hash_digest_len)==0))
	      {
		found_me = TRUE;/*本端未经过NAT*/
	      }

	    if ( (pbs_left(&p->pbs) == st->st_oakley.prf_hasher->hash_digest_len)
		 && (memcmp(p->pbs.cur, hash_him
			    , st->st_oakley.prf_hasher->hash_digest_len)==0))
	      {
		found_him = TRUE;/*对端未经过NAT*/
	      }

	    i++;
	  }

	DBG(DBG_NATT,
	    DBG_log("NAT_TRAVERSAL hash=%d (me:%d) (him:%d)"
		    , i, found_me, found_him));

	if(!found_me) {
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_ME);/*本端经过NAT*/
	    st->hidden_variables.st_natd = md->sender;
	}

        memset(&st->hidden_variables.st_natd,0,sizeof(st->hidden_variables.st_natd));
	anyaddr(AF_INET, &st->hidden_variables.st_natd);

	if(!found_him) {
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);/*对端经过NAT*/
	    st->hidden_variables.st_natd = md->sender;
	}


	if(st->st_connection->forceencaps) {/*如果需要强制使用UDP封装双方都需要NAT-D*/
	    DBG(DBG_NATT,
		DBG_log("NAT_TRAVERSAL forceencaps enabled"));

	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_ME);
	    st->hidden_variables.st_natd = md->sender;
	}
}

```



### 6. build_ke源码分析

```c

stf_status build_ke(struct pluto_crypto_req_cont *cn
		    , struct state *st
		    , const struct oakley_group_desc *group
		    , enum crypto_importance importance)
{
    struct pluto_crypto_req rd;
    struct pluto_crypto_req *r = &rd;
    err_t e;
    bool toomuch = FALSE;
/*初始化加密请求*/
    pcr_init(r, pcr_build_kenonce, importance);
    r->pcr_d.kn.oakley_group   = group->group;

    cn->pcrc_serialno = st->st_serialno;
	/*申请制作加密材料请求*/
    e= send_crypto_helper_request(r, cn, &toomuch);

    if(e != NULL) {/*加密失败*/
	loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
	if(toomuch) {
	    return STF_TOOMUCHCRYPTO;
	} else {
	    return STF_FAIL;
	}
    } else if(!toomuch) {/*加密任务繁忙，先挂起等待再次调度*/
	st->st_calculating = TRUE;
	delete_event(st);
	event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);
	return STF_SUSPEND;
    } else {
	/* we must have run the continuation directly, so
	 * complete_v1_state_transition already got called.
	 * 由于我们已经手动执行了main_inR1_outI2_continue(),该函数最终会调用到complete_v1_state_transition
	 * 因此在(process_v1_state_xxx流程中不必再此执行状态转换函数。因此返回STF_INLINE，当再次到complete_v1_state_transition
	 *判断返回值为它，则不再执行此函数。)
	 */
	return STF_INLINE;
    }
}
```



### 7. main_inI2_outR2_continue源码分析

```c
static void
main_inI2_outR2_continue(struct pluto_crypto_req_cont *pcrc
			 , struct pluto_crypto_req *r
			 , err_t ugh)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    stf_status e;
    ... ... 
    set_suspended(st, NULL);	/* no longer connected or suspended */

    set_cur_state(st);

    st->st_calculating = FALSE;
    e = main_inI2_outR2_tail(pcrc, r);/*构造应答报文*/

    if(ke->md != NULL) {
        complete_v1_state_transition(&ke->md, e);/*发送报文并完后后续处理工作*/
        if(ke->md) release_md(ke->md);
    }
    reset_cur_state();
}
```



### 8. main_inI2_outR2_tail源码分析

```c

/*
 * this routine gets called after any DH exponentiation that needs to be done
 * has been done, and we are ready to send our g^y.
 */
stf_status
main_inI2_outR2_tail(struct pluto_crypto_req_cont *pcrc
		     , struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *st = md->st;

    /* send CR if auth is RSA and no preloaded RSA public key exists*/
    bool send_cr = FALSE;

    /**************** build output packet HDR;KE;Nr ****************/

/*如果以下四个条件同时满足，则通过需要发送证书。。*/
    send_cr = !no_cr_send							/*配置中允许发送证书*/
	&& (st->st_oakley.auth == OAKLEY_RSA_SIG)		/*使用RSA签名*/
	&& !has_preloaded_public_key(st)				/*未加载未共享秘钥*/
	&& st->st_connection->spd.that.ca.ptr != NULL;	/*对端证书非空*/

    /* HDR out */
    echo_hdr(md, FALSE, ISAKMP_NEXT_KE);

    /* KE out *//*添加KE载荷，并将其存储在st->st_gr*/
    if (!ship_KE(st, r, &st->st_gr
		 , &md->rbody, ISAKMP_NEXT_NONCE))
	{
	    osw_abort();
	return STF_INTERNAL_ERROR;
	}

#ifdef DEBUG
 {
    /* Nr out */
    int next_payload;
    next_payload = ISAKMP_NEXT_NONE;

    if(cur_debugging & IMPAIR_BUST_MR2)
    {
	next_payload = ISAKMP_NEXT_VID;
    }
    if(send_cr)
    {
        next_payload = ISAKMP_NEXT_CR;
    }
    if (!ship_nonce(&st->st_nr, r
		    , &md->rbody
		    , next_payload
		    , "Nr"))
	return STF_INTERNAL_ERROR;

    if (cur_debugging & IMPAIR_BUST_MR2)
    {
	/* generate a pointless large VID payload to push message over MTU */
	pb_stream vid_pbs;

	if (!out_generic((send_cr)? ISAKMP_NEXT_CR : ISAKMP_NEXT_NONE,
	    &isakmp_vendor_id_desc, &md->rbody, &vid_pbs))
	    return STF_INTERNAL_ERROR;
	if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&vid_pbs);
    }
 }
#else
    /* Nr out *//*添加NONCE载荷，并将其存储在st->st_nr*/
    if (!ship_nonce(&st->st_nr, r
		    , &md->rbody
		    , (send_cr)? ISAKMP_NEXT_CR : ISAKMP_NEXT_NONE
		    , "Nr"))
	return STF_INTERNAL_ERROR;
#endif

    /* CR out *//*如果需要发送证书*/
    if (send_cr)
    {
	if (st->st_connection->kind == CK_PERMANENT)/*双方连接固定,即两端的IP的确定的*/
	{
	    if (!build_and_ship_CR(CERT_X509_SIGNATURE /*添加对端证书载荷*/
				   , st->st_connection->spd.that.ca
				   , &md->rbody, ISAKMP_NEXT_NONE))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    generalName_t *ca = NULL;
	/*查询可用的证书   ???*/
	    if (collect_rw_ca_candidates(md, &ca))/*收集所有可用证书,并全部加载到ca链表上*/
	    {
		generalName_t *gn;

		for (gn = ca; gn != NULL; gn = gn->next)
		{
		    if (!build_and_ship_CR(CERT_X509_SIGNATURE, gn->name/*将所有的可用证书加载到链表上*/
		    , &md->rbody
		    , gn->next == NULL ? ISAKMP_NEXT_NONE : ISAKMP_NEXT_CR))
			return STF_INTERNAL_ERROR;
		}
		free_generalNames(ca, FALSE);/*释放可用证书链表*/
	    }
	    else
	    {/*确实没有找到可用的证书，则填充一个空的证书载荷*/
		if (!build_and_ship_CR(CERT_X509_SIGNATURE, empty_chunk
		, &md->rbody, ISAKMP_NEXT_NONE))
		    return STF_INTERNAL_ERROR;
	    }
	}
    }

#ifdef NAT_TRAVERSAL
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD) {
	if (!nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))/*添加NAT-D载荷*/
	    return STF_INTERNAL_ERROR;
    }
#endif

    /* finish message */
    close_message(&md->rbody);
/*********************************************

	使  用  DH  算  法  开  始  制  作  密  钥


***********************************************/
    /*
     * next message will be encrypted, so, we need to have
     * the DH value calculated. We can do this in the background,
     * sending the reply right away. We have to be careful on the next
     * state, since the other end may reply faster than we can calculate
     * things. If it is the case, then the packet is placed in the
     * continuation, and we let the continuation process it. If there
     * is a retransmit, we keep only the last packet.
     *
     * Also, note that this is not a suspended state, since we are
     * actually just doing work in the background.
     *
     */
    {
    /* Looks like we missed perform_dh() declared at
     * programs/pluto/pluto_crypt.h as external and implemented nowhere.
     * Following code regarding dh_continuation allocation seems useless
     * as it's never used. At least, we should free it.
     */
	struct dh_continuation *dh = alloc_thing(struct dh_continuation
						 , "main_inI2_outR2_tail");
	stf_status e;

	dh->md = NULL;
	dh->serialno = st->st_serialno;
	pcrc_init(&dh->dh_pcrc);
	dh->dh_pcrc.pcrc_func = main_inI2_outR2_calcdone;
	passert(st->st_suspended_md == NULL);

	DBG(DBG_CONTROLMORE
	    , DBG_log("main inI2_outR2: starting async DH calculation (group=%d)", st->st_oakley.group->group));

	e = start_dh_secretiv(&dh->dh_pcrc, st
			      , st->st_import
			      , RESPONDER
			      , st->st_oakley.group->group);

	DBG(DBG_CONTROLMORE,
	    DBG_log("started dh_secretiv, returned: stf=%s\n"
		    , stf_status_name(e)));

	if(e == STF_FAIL) {
	    loglog(RC_LOG_SERIOUS, "failed to start async DH calculation, stf=%s\n"
		   , stf_status_name(e));
	    return e;
	}

	/* we are calculating in the background, so it doesn't count */
	if(e == STF_SUSPEND) {
	    st->st_calculating = FALSE;
	}
    }
    return STF_OK;
}
```



### 9. main_inI2_outR2_calcdone源码分析

```c

static void
main_inI2_outR2_calcdone(struct pluto_crypto_req_cont *pcrc
			 , struct pluto_crypto_req *r
			 , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct state *st;

    DBG(DBG_CONTROLMORE
	, DBG_log("main inI2_outR2: calculated DH finished"));

    st = state_with_serialno(dh->serialno);
    if(st == NULL) {
	openswan_log("state %ld disappeared during crypto\n", dh->serialno);
	return;
    }

    set_cur_state(st);
    if(ugh) {
	loglog(RC_LOG_SERIOUS, "DH crypto failed: %s\n", ugh);
	return;
    }
/*将生成的三把秘钥、DH-IV等信息存储在状态上*/
    finish_dh_secretiv(st, r);
    if(!r->pcr_success) {
        loglog(RC_LOG_SERIOUS, "DH crypto failed, invalid keys");
        return;
    }

    ikev2_validate_key_lengths(st);

    st->hidden_variables.st_skeyid_calculated = TRUE;
    update_iv(st);/*更新IV值*/
    /* XXX: Do we need to free dh here? If so, how about the other exits?
     * pfree(dh); dh = NULL;
     */

    /*
     * if there was a packet received while we were calculating, then
     * process it now.
     */
     /*如果在计算秘钥的过程中收到新的报文则现在再处理该报文*/
    if(st->st_suspended_md != NULL) {
	struct msg_digest *md = st->st_suspended_md;

	set_suspended(st, NULL);
	process_packet_tail(&md);
	if(md != NULL) {
	    release_md(md);
	}
    }
    reset_cur_state();
    return;
}

```













































































