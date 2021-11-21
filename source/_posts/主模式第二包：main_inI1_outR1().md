---
title: 主模式第二包：main_inI1_outR1()
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

`main_inI1_outR1()`函数是ISAKMP协商过程中第二包的核心处理函数，同时也是响应端口的首包。这里我们主要说明`main_inI1_outR1`的处理流程，关于`main_inI1_outR1`的上下文环境暂不叙述，留给后面的文章进行更新。
<!--more-->
ISAKMP协商报文的处理流程都比较复杂，一个函数有几百行都是很常见的，因此个人学习期间难免有遗漏和理解错误的地方，请大家多多批评指正。

### 2. `main_inI1_outR1()`处理流程图

![image-20200520004303196](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205011.png)

![image-20200520004352037](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205022.png)

### 3. `main_inI1_outR1()源码`



```c
/* State Transition Functions.
 *
 * The definition of state_microcode_table in demux.c is a good
 * overview of these routines.
 *
 * - Called from process_packet; result handled by complete_v1_state_transition
 * - struct state_microcode member "processor" points to these
 * - these routine definitionss are in state order
 * - these routines must be restartable from any point of error return:
 *   beware of memory allocated before any error.
 * - output HDR is usually emitted by process_packet (if state_microcode
 *   member first_out_payload isn't ISAKMP_NEXT_NONE).
 *
 * The transition functions' functions include:
 * - process and judge payloads
 * - update st_iv (result of decryption is in st_new_iv)
 * - build reply packet
 */

/* Handle a Main Mode Oakley first packet (responder side).
 * HDR;SA --> HDR;SA
 */

/********************************
*main_inI1_outR1函数被process_packet函数调用
*它的返回结果由complete_v1_state_transition处理
*
*********************************/
stf_status
main_inI1_outR1(struct msg_digest *md)
{
#ifdef DMALLOC
     if (_dm_initialized != 0) {
	/* log unfreed pointers that have been added to the heap since mark */
	dmalloc_log_changed(_dm_mark, 1, 0, 1);
	dmalloc_log_stats ();
     }
     _dm_mark = dmalloc_mark() ;
     _dm_initialized = 1;
#endif
/*接收到的数据包中的SA载荷部分*/
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
    struct state *st;
    struct connection *c;
/*准备作为应答的SA载荷缓冲区*/
    pb_stream r_sa_pbs;
    lset_t policy_hint = 0;

    /* we are looking for an OpenPGP Vendor ID sent by the peer */
    bool openpgp_peer = FALSE;

    /* Determin how many Vendor ID payloads we will be sending */
    int next;
    int numvidtosend = 1;  /* we always send DPD VID */
/*至少会发送DPD的VID,因此初始值为1*/
#ifdef NAT_TRAVERSAL   /*支持NAT-T,则增加一个nat-t探测的VID*/
    if (md->quirks.nat_traversal_vid && nat_traversal_enabled) {
	DBG(DBG_NATT, DBG_log("nat-t detected, sending nat-t VID"));
	numvidtosend++;
    }
#endif
/*如果预定义了PLUUO VID 或openpgp 对端, 增加VID 数量*/
#if SEND_PLUTO_VID || defined(openpgp_peer)
    numvidtosend++;
#endif

#if defined(openpgp_peer)
    {
	    struct payload_digest *p;
	   /*遍历接收到的数据包中的VID 载荷链表*/
	    for (p = md->chain[ISAKMP_NEXT_VID]; p != NULL; p = p->next)
		{
		    int vid_len = sizeof(pgp_vendorid) - 1 < pbs_left(&p->pbs)
			? sizeof(pgp_vendorid) - 1 : pbs_left(&p->pbs);

		    /*检查是否是pgp VID, 是则设置openpgp_peer 标志为TRUE*/
		    if (memcmp(pgp_vendorid, p->pbs.cur, vid_len) == 0)
			{
			    openpgp_peer = TRUE;
			    DBG(DBG_PARSING,
				DBG_log("we have an OpenPGP peer")
				)
				}
		}
    }
#endif

    /*根据接收到的数据包的目的地址,目的端口,源地址,源端口查找连接结构*/
    /* random source ports are handled by find_host_connection */
    c = find_host_connection(ANY_MATCH, &md->iface->ip_addr, pluto_port500
                             , KH_IPADDR
			     , &md->sender
			     , md->sender_port, LEMPTY, POLICY_IKEV1_DISABLE, &policy_hint);

    if (c == NULL)/*如果没找到*/
    {
	pb_stream pre_sa_pbs = sa_pd->pbs;
	lset_t policy = preparse_isakmp_sa_body(&pre_sa_pbs);
	/*
	 * If there is XAUTH VID, copy it to policies.
	 */
	if (md->quirks.xauth_vid == TRUE)
	{
	  policy |= POLICY_XAUTH;
	}
	/* See if a wildcarded connection can be found.
	 * We cannot pick the right connection, so we're making a guess.
	 * All Road Warrior connections are fair game:
	 * we pick the first we come across (if any).
	 * If we don't find any, we pick the first opportunistic
	 * with the smallest subnet that includes the peer.
	 * There is, of course, no necessary relationship between
	 * an Initiator's address and that of its client,
	 * but Food Groups kind of assumes one.
	 */
	{
	// 可能是那种未定义对方地址的动态连接, 将源地址条件置空,重新查找连接,
       // 可能会找到多个连接结构,返回的是一个链表
	    struct connection *d;
	    d = find_host_connection(ANY_MATCH, &md->iface->ip_addr, pluto_port500
                                     , KH_ANY
				     , (ip_address*)NULL
				     , md->sender_port, policy, POLICY_IKEV1_DISABLE, &policy_hint);
           // 遍历链表
	    for (; d != NULL; d = d->IPhp_next)
	    {
	       // GROUP 类型连接不考虑
		if (d->kind == CK_GROUP)
		{
		    /* ignore */
		}
		else
		{
		// 如果连接类型为模板型而且没定义OE, 该连接可用于处理该数据包, 连接找到,中断循环
		    if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPO))
		    {
			/* must be Road Warrior: we have a winner */
			c = d;
			break;
		    }

		    /* Opportunistic or Shunt: pick tightest match */
			// 比较数据包源地址是否匹配连接中对方地址的定义
		    if (addrinsubnet(&md->sender, &d->spd.that.client)
		      // 而且目前可用连接为空,或目前可用连接的地址范围比新找到的连接范围大, 更新可用连接
		    && (c == NULL || !subnetinsubnet(&c->spd.that.client, &d->spd.that.client)))
			c = d;
		}
	    }
	}
       // 如果没找到连接, 该数据包处理不了, 返回忽略该数据包
	if (c == NULL)
	{
	    loglog(RC_LOG_SERIOUS, "initial Main Mode message received on %s:%u"
		" but no connection has been authorized%s%s"
		, ip_str(&md->iface->ip_addr), ntohs(portof(&md->iface->ip_addr))
		, (policy != LEMPTY) ? " with policy=" : ""
		, (policy != LEMPTY) ? bitnamesof(sa_policy_bit_names, policy) : "");

            if(policy_hint & POLICY_IKEV1_DISABLE) {
                md->note = INVALID_MAJOR_VERSION;
                return STF_FAIL;
            }

	    /* XXX notification is in order! */
	    return STF_IGNORE;
	}/* 否则如果不是模板类型连接(动态连接), 返回忽略*/
	else if (c->kind != CK_TEMPLATE)
	{
	    loglog(RC_LOG_SERIOUS, "initial Main Mode message received on %s:%u"
		" but \"%s\" forbids connection"
		, ip_str(&md->iface->ip_addr), pluto_port500, c->name);
	    /* XXX notification is in order! */
	    return STF_IGNORE;
	}
	else
	{
	    /* Create a temporary connection that is a copy of this one.
	     * His ID isn't declared yet.
	     */
	   DBG(DBG_CONTROL, DBG_log("instantiating \"%s\" for initial Main Mode message received on %s:%u"
		, c->name, ip_str(&md->iface->ip_addr), pluto_port500));
	// 将模板连接进行实例化, 根据模板连接新生成一个新连接结构, 填充对方地址
	    c = rw_instantiate(c, &md->sender
			       , NULL, NULL);
	}
     } else {
	/* we found a non-wildcard conn. double check if it needs instantiation anyway (eg vnet=) */
	if ((c->kind == CK_TEMPLATE) && c->spd.that.virt) {
	   DBG(DBG_CONTROL, DBG_log("local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation"));
	   c = rw_instantiate(c,&md->sender,NULL,NULL);
	}
    }

#ifdef XAUTH
    if(c->spd.this.xauth_server || c->spd.this.xauth_client)
    {
        numvidtosend++;
    }
#endif
    /* Set up state */
// 新分配状态结构
    md->st = st = new_state();
#ifdef XAUTH
    passert(st->st_oakley.xauth == 0);
#endif
    st->st_connection = c;
    st->st_remoteaddr = md->sender;
    st->st_remoteport = md->sender_port;
    st->st_localaddr  = md->iface->ip_addr;
    st->st_localport  = md->iface->port;
    st->st_interface  = md->iface;

    /* IKE version numbers -- used mostly in logging */
    st->st_ike_maj        = md->maj;
    st->st_ike_min        = md->min;

    set_cur_state(st);	/* (caller will reset cur_state) */
    st->st_try = 0;	/* not our job to try again from start */
    st->st_policy = c->policy & ~POLICY_IPSEC_MASK;	/* only as accurate as connection */
    // 状态类型为R0(接收到初始化包)
    change_state(st, STATE_MAIN_R0);

    // 复制对方的cookie
    memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);

    // 生成本地的cookie
    get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);

    // 将新状态插入到状态哈希表
    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    st->st_doi = ISAKMP_DOI_IPSEC;
    st->st_situation = SIT_IDENTITY_ONLY; /* We only support this */

    /* copy the quirks we might have accumulated */
	// 复制特殊标志
    copy_quirks(&st->quirks,&md->quirks);

    if ((c->kind == CK_INSTANCE) && (c->spd.that.host_port_specific))
    {
       openswan_log("responding to Main Mode from unknown peer %s:%u"
	    , ip_str(&c->spd.that.host_addr), c->spd.that.host_port);
    }
    else if (c->kind == CK_INSTANCE)
    {
	openswan_log("responding to Main Mode from unknown peer %s"
	    , ip_str(&c->spd.that.host_addr));
    }
    else
    {
	openswan_log("responding to Main Mode");
    }

    /* parse_isakmp_sa also spits out a winning SA into our reply,
     * so we have to build our reply_stream and emit HDR before calling it.
     */

    /* HDR out.
     * We can't leave this to comm_handle() because we must
     * fill in the cookie.
     */
     // 以下开始填充要发送的回应包信息
     
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");
    {
      // 填充ISAKMP头部
	struct isakmp_hdr r_hdr = md->hdr;

	r_hdr.isa_flags &= ~ISAKMP_FLAG_COMMIT;	/* we won't ever turn on this bit */
	memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	r_hdr.isa_np = ISAKMP_NEXT_SA;
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
	    return STF_INTERNAL_ERROR;
    }
	
    // 填充SA 结构信息
    /* start of SA out */
    {
	struct isakmp_sa r_sa = sa_pd->payload.sa;

	/* if we to send any VID, then set the NEXT payload correctly */
	r_sa.isasa_np = numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if (!out_struct(&r_sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
	    return STF_INTERNAL_ERROR;
    }

    /* SA body in and out */
	/*解析对方的SA,根据他的建议载荷来确定本地是否支持，如果支持则回复支持的算法信息，并构建应答SA*/
    RETURN_STF_FAILURE(parse_isakmp_sa_body(&sa_pd->pbs, &sa_pd->payload.sa
					    , &r_sa_pbs, FALSE, st));

	/*填充VID*/
    if (SEND_PLUTO_VID || openpgp_peer)
    {
	char *vendorid = (openpgp_peer) ?
	    pgp_vendorid : pluto_vendorid;

	next = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if (!out_generic_raw(next, &isakmp_vendor_id_desc, &md->rbody
			     , vendorid, strlen(vendorid), "Vendor ID"))
	    return STF_INTERNAL_ERROR;
    }

    /*
     * NOW SEND VENDOR ID payloads
     */
	/*填充DPD*/
    /* Announce our ability to do RFC 3706 Dead Peer Detection */
    next = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
    if( !out_vid(next, &md->rbody, VID_MISC_DPD))
      return STF_INTERNAL_ERROR;

#ifdef XAUTH
    /* If XAUTH is required, insert here Vendor ID */
    if(c->spd.this.xauth_server || c->spd.this.xauth_client)
    {
	    next = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	    if (!out_vendorid(next, &md->rbody, VID_MISC_XAUTH))
	       return STF_INTERNAL_ERROR;
    }
#endif
#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT, DBG_log("sender checking NAT-T: %d and %d"
				, nat_traversal_enabled
				, md->quirks.nat_traversal_vid));
   /*填充NAT-T的VID*/
    if (md->quirks.nat_traversal_vid && nat_traversal_enabled) {

        next = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	/* reply if NAT-Traversal draft is supported */
	/*nat_traversal_vid_to_method:将VID转换为对应的标准*/
	st->hidden_variables.st_nat_traversal = nat_traversal_vid_to_method(md->quirks.nat_traversal_vid);
	/*填充VID载荷，这里的NAT-T VID选择的是对方发来的最大的NAT-T 的VID,也就是说选用最新的NAT-T标准*/
	if ((st->hidden_variables.st_nat_traversal) && (!out_vendorid(next,
	    &md->rbody, md->quirks.nat_traversal_vid))) {
	    return STF_INTERNAL_ERROR;
	}
    }
#endif


#ifdef DEBUG
    /* if we are not 0 then something went very wrong above */
    if(numvidtosend != 0) {
	openswan_log("payload alignment problem please check the code in main_inI1_outR1 (num=%d)", numvidtosend);
    }
#endif
/*应答报文封装完毕，填充长度字段*/
    close_message(&md->rbody);

    /* save initiator SA for HASH */
    clonereplacechunk(st->st_p1isa, sa_pd->pbs.start, pbs_room(&sa_pd->pbs), "sa in main_inI1_outR1()");

    return STF_OK;
}
```



### 4. `parse_isakmp_sa_body()源码`

暂略。

