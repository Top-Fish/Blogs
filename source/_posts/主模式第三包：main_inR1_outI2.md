---
title: 主模式第三包：main_inR1_outI2
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

`main_inR1_outI2()`函数是ISAKMP协商过程中==第三包的核心处理函数的入口==。这里我们主要说明`main_inR1_outI2`的函数调用关系、处理流程以及对源码的注释分析，关于`main_inR1_outI2`的上下文环境暂不叙述，留给后面的文章进行更新。
<!--more-->
ISAKMP协商报文的处理流程都比较复杂，一个函数有几百行都是很常见的，因此个人学习期间难免有遗漏和理解错误的地方，请大家多多批评指正。

对于源码的学习，我并没有把每一行进行备注，而是将自己认为的关键点做了注释或者标注。

---



### 2. 函数调用关系

> 注意：这里我把收到对方报文后的处理流程也添加上了，主要是在学习源码过程中遇到`complete_v1_state_transition`执行了两次。第二次会检测第一次的返回值，因此不会重复的发送报文更新状态。

- process_v1_packet
  - process_packet_tail
    - smc->processor(md)
      - main_inR1_outI2
        - build_ke
          - send_crypto_helper_request
            - pluto_do_crypto_op
            - main_inR1_outI2_continue
              - main_inR1_outI2_tail
                - init_pbs
                - ship_KE
                - ship_nonce
                - nat_traversal_add_natd
                - close_message
                - insert_state
              - complete_v1_state_transition
    - complete_v1_state_transition

![image-20200521075841786](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120204847.png)

### 3. 第三个报文流程图

由于第三个报文的核心处理函数包含多个，不仅仅包含`main_inR1_outI2`, 因此这里会将涉及的关键函数接口都添加到流程图中，方便根据函数定位对应的功能。

---

- [x] **解析对端发送的SA载荷，确定对端选择的算法，并将其存储在状态/连接上**
- [x] **生成秘钥交换材料和Nonce信息**
- [x] ==构造应答报文(第四个报文）==
  - [x] **填充KE载荷和Nonce载荷**。

---

![image-20200520231919967](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120204851.png)



### 4. main_inR1_outI2源码注释

- [x] 解析收到的第二个报文，确定对端选择的算法，并将算法存储在状态结构上
- [x] 申请生成交换密钥信息

```c

stf_status
main_inR1_outI2(struct msg_digest *md)
{
    struct state *const st = md->st;

    /* verify echoed SA */
    {/*md->chain为解析完毕的收到的报文,下标为np的值*/
	struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

	 /*解析对端SA, 由于无需填充应答SA因此第三个参数为NULL*/
	RETURN_STF_FAILURE(parse_isakmp_sa_body(&sapd->pbs
						, &sapd->payload.sa
						, NULL, TRUE, st));
    }

#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT, DBG_log("sender checking NAT-T: %d and %d"
				 , nat_traversal_enabled
				 , md->quirks.nat_traversal_vid))

    if (nat_traversal_enabled && md->quirks.nat_traversal_vid) {/*获取NAT-T采用的标准*/
	st->hidden_variables.st_nat_traversal = nat_traversal_vid_to_method(md->quirks.nat_traversal_vid);
	openswan_log("enabling possible NAT-traversal with method %s"
	     , bitnamesof(natt_type_bitnames, st->hidden_variables.st_nat_traversal));
    }
#endif

    {/*密钥交换*/
	struct ke_continuation *ke = alloc_thing(struct ke_continuation
						 , "outI2 KE");
	ke->md = md;

	passert(st->st_sec_in_use==FALSE);/*是否已经加密,是的话，状态有误，返回退出*/
	pcrc_init(&ke->ke_pcrc);
	ke->ke_pcrc.pcrc_func = main_inR1_outI2_continue;
	set_suspended(st, md);
        /*构建秘钥交换载荷信息*/
	return build_ke(&ke->ke_pcrc, st, st->st_oakley.group, st->st_import);
    }
}
```

## 5. build_ke源码注释

- [x] 初始化并发送加密请求
  - [ ] 生成加密材料、Nonce载荷、构建应答报文在`send_crypto_helper_request`及其以后。
- [x] 完成报文发送后的后续操作

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
	/*发送加密请求*/
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
	 * 由于我们已经手动执行了main_inR1_outI2_continue(),该函数最终会调用到complete_v1_state_transition, 因此在(process_v1_state_xxx流程中不必再此执行状态转换函数。因此返回STF_INLINE，当再次到complete_v1_state_transition判断返回值为它，则不再执行此函数。)
	 */
	return STF_INLINE;
    }
}
```

## 6. send_crypto_helper_request源码注释

- [x] 生成秘钥信息(KE信息、Nonce信息)，并存储在r中；
- [x] 执行后续处理函数：`main_inR1_outI2_continue`

```c
/*
 * this function is called with a request to do some cryptographic operations
 * along with a continuation structure, which will be used to deal with
 * the response.
 *
 * This may fail if there are no helpers that can take any data, in which
 * case an error is returned.
 *
 */
err_t send_crypto_helper_request(struct pluto_crypto_req *r
				 , struct pluto_crypto_req_cont *cn
				 , bool *toomuch)
{
    struct pluto_crypto_worker *w;
    int cnt;

    /* do it all ourselves? */
    if(pc_workers == NULL) {/*据说一般会执行此分支*/
	reset_cur_state();

/*生成nonce值相关*/
#ifdef HAVE_LIBNSS
	pluto_do_crypto_op(r,pc_helper_num);
#else
	pluto_do_crypto_op(r);
#endif
	/* call the continuation */
	(*cn->pcrc_func)(cn, r, NULL);//1 /*执行后续函数，如main_inR1_outI2_continue等*/

	/* indicate that we did everything ourselves */
	*toomuch = TRUE;

	pfree(cn);
	return NULL;
    }
    /*后续代码尚未整理，暂不考虑*/
    ... ... 
}
```

## 7. send_crypto_helper_request源码注释

- [x] 通过`main_inR1_outI2_tail`构建应答报文
- [x] 通过`complete_v1_state_transition`完成报文的发送和后续的状态切换等。

```c
/*
 * STATE_MAIN_I1: HDR, SA --> auth dependent
 * PSK_AUTH, DS_AUTH: --> HDR, KE, Ni
 *
 * We do heavy computation here. For Main Mode, this is mostly okay,
 * since have already done a return routeability check.
 *
 */
static void
main_inR1_outI2_continue(struct pluto_crypto_req_cont *pcrc
			 , struct pluto_crypto_req *r
			 , err_t ugh)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    stf_status e;

    ... ... /*中间调试信息代码略去*/

    e = main_inR1_outI2_tail(pcrc, r);/*构造应答报文(第四包)*/

    if(ke->md != NULL) {
	complete_v1_state_transition(&ke->md, e);/*完成状态转换、发送报文，...*/
	if(ke->md) release_md(ke->md);
    }

    reset_cur_state();
}
```

## 8. main_inR1_outI2_tail源码注释

- [x] 构建ISAKMP头部信息
- [x] 构建KE载荷
- [x] 构建Nonce载荷
- [x] 构建NAT-d载荷
- [x] 载荷添加完毕，关闭应答buf, 确定ISAKMP报文长度并填充长度字段。

```c

/* STATE_MAIN_I1: HDR, SA --> auth dependent
 * PSK_AUTH, DS_AUTH: --> HDR, KE, Ni
 *
 * The following are not yet implemented:
 * PKE_AUTH: --> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * RPKE_AUTH: --> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 *                <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
 *
 * We must verify that the proposal received matches one we sent.
 */
static stf_status
main_inR1_outI2_tail(struct pluto_crypto_req_cont *pcrc
		     , struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;

    /**************** build output packet HDR;KE;Ni ****************/
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out.
     * We can't leave this to comm_handle() because the isa_np
     * depends on the type of Auth (eventually).
     */
     /*下一个载荷：密钥交换. 填充ISAKMP头部信息*/
    echo_hdr(md, FALSE, ISAKMP_NEXT_KE);/*reply_stream-----md->rbody*/

    /* KE out */
/*填充密钥交换载荷，同时状态上记录了密钥的相关信息*/
    if (!ship_KE(st, r , &st->st_gi
		 , &md->rbody, ISAKMP_NEXT_NONCE))
	return STF_INTERNAL_ERROR;
    
/*填充Nonce载荷*/
#ifdef DEBUG
    /* Ni out */
    if (!ship_nonce(&st->st_ni, r, &md->rbody
		    , (cur_debugging & IMPAIR_BUST_MI2)? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		    , "Ni"))
	return STF_INTERNAL_ERROR;

    if (cur_debugging & IMPAIR_BUST_MI2)
    {
	/* generate a pointless large VID payload to push message over MTU */
	pb_stream vid_pbs;

	if (!out_generic(ISAKMP_NEXT_NONE, &isakmp_vendor_id_desc, &md->rbody
	    , &vid_pbs))
	    return STF_INTERNAL_ERROR;
	if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&vid_pbs);
    }
#else
    /* Ni out */
    if (!ship_nonce(&st->st_ni, r, &md->rbody, ISAKMP_NEXT_NONE, "Ni"))
	return STF_INTERNAL_ERROR;
#endif
/*填充NAT-D载荷*/
#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT, DBG_log("NAT-T checking st_nat_traversal for NAT_T_WITH_NATD"));
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD) {
        DBG(DBG_NATT, DBG_log("NAT-T found NAT_T_WITH_NATD"));
	if (!nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
	    return STF_INTERNAL_ERROR;
    }
#endif

    /* finish message 报文构建结束，确定报文长度*/
    close_message(&md->rbody);

    /* Reinsert the state, using the responder cookie we just received */
	//将st从哈希表中删除
    unhash_state(st);/*unhash_state：使用二级指针从双向链表中删除st节点*/
    memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
	/*重新计算hash值，并插入全局状态链表中*/
    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    return STF_OK;
}
```

## 9. NAT-D载荷中哈希值说明

在NAT-D载荷中，hash值的计算公式为：
$$
HASH(CKY-I | CKY-R | IP | PORT)
$$
即分别计算发起者cookie、相应者cookie、IP、端口四个信息的哈希值。对端收到后通过计算报文信息的哈希值和报文中的NAT-D载荷的哈希值相比较，以此来确定中间是否存在NAT设备。

```c

bool nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
			    struct msg_digest *md)
{
	unsigned char hash[MAX_DIGEST_LEN];
	struct state *st = md->st;
	unsigned int nat_np;
	const ip_address *first, *second;
	unsigned short firstport, secondport;

	passert(st->st_oakley.prf_hasher);

	DBG(DBG_EMITTING|DBG_NATT, DBG_log("sending NAT-D payloads"));

	nat_np = (st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES
		  ? ISAKMP_NEXT_NATD_RFC : ISAKMP_NEXT_NATD_DRAFTS);
    
	if (!out_modify_previous_np(nat_np, outs)) {/*修改上一个载荷的np字段*/
		return FALSE;
	}

	/*获取本端和对端的IP和端口*/
	first      = &(md->sender);
	firstport  = ntohs(st->st_remoteport);
	second     = &(md->iface->ip_addr);
	secondport = ntohs(st->st_localport);

	if(st->st_connection->forceencaps) {/*强制封装*/
		DBG(DBG_NATT, DBG_log("NAT-T: forceencaps=yes, so mangling hash to force NAT-T detection"));
		firstport=secondport=0;
	}

	/**
	 * First one with sender IP & port
	 */
	 /*计算对端的哈希值: rcookie, icookie, ip, port*/
        _natd_hash(st->st_oakley.prf_hasher, hash, st->st_icookie
		       , is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie
		       , first, firstport);

	if (!out_generic_raw(nat_np, &isakmp_nat_d, outs
			     , hash
			     , st->st_oakley.prf_hasher->hash_digest_len
			     , "NAT-D")) {
	    return FALSE;
	}

	/**
	 * Second one with my IP & port
	 */
	 /*计算本端的哈希值: rcookie, icookie, ip, port*/
        _natd_hash(st->st_oakley.prf_hasher, hash
		       , st->st_icookie
		       , is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie
		       , second, secondport);
	return (out_generic_raw(np, &isakmp_nat_d, outs,
		hash, st->st_oakley.prf_hasher->hash_digest_len, "NAT-D"));
}

```



