---
title: 快速模式第一包之quick_outI1()
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

openswan源码中有关隧道协商的文章已经比较久没有更新了，那么从这篇开始再重新回到更新流程上。这中间停了将近2个月，第一个月几乎没有更新任何博客，而第二个月主要整理翻译QAT相关的文章，接下来我将继续更新openswan源码相关的内容。

下面开始介绍IPSec 快速模式协商流程中的第①包，主要函数的入口为**quick_outI1()**：
<!--more-->
![image-20200826002057928](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205311.png)

### 2. quick_outI1()流程图

![image-20200826003329910](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205313.png)

### 3. quick_outI1()源码分析

`quick_outI1()`接口是第二阶段快速模式第一包的入口函数，它最主要的工作就是将==第一阶段协商的ipsecsa状态信息转换为第二阶段的状态信息==。通过`duplicate_state`实现状态的拷贝，然后将新的状态插入到全局的状态表中。之后就是根据隧道的配置信息(PFS, 算法信息)等做秘钥申请等准备工作。

- [x] **复制第一阶段ipsecsa状态，并将其插入全局状态表中**
- [x] **显示第二阶段算法相关的debug信息**
- [x] **根据配置做秘钥申请**

```c
stf_status
quick_outI1(int whack_sock
	    , struct state *isakmp_sa
	    , struct connection *c
	    , lset_t policy
	    , unsigned long try
	    , so_serial_t replacing
	    , struct xfrm_user_sec_ctx_ike * uctx UNUSED
	    )
{
    struct state *st = duplicate_state(isakmp_sa);/*复制第一阶段的状态,包括了所有的基本信息*/
    struct qke_continuation *qke;
    stf_status e;
    const char *pfsgroupname;
    char p2alg[256];

    st->st_whack_sock = whack_sock;
    st->st_connection = c;/*从这里可以看出每一个连接c可对应多个state结构，比如一个phase1,一个phase2.因此在隧道状态时需要特别注意*/
    passert(c != NULL);

    if(st->st_calculating) {
	return STF_IGNORE; 
    }

    set_cur_state(st);	/* we must reset before exit */
    st->st_policy = policy;
    st->st_try = try;

#ifdef HAVE_LABELED_IPSEC
    st->sec_ctx=NULL;
    if(uctx != NULL) {
    st->sec_ctx = clone_thing(*uctx, "sec ctx structure");
    DBG(DBG_CONTROL, DBG_log("pending phase 2 with security context %s, %d", st->sec_ctx->sec_ctx_value, st->sec_ctx->ctx_len));
    }
#endif
	/*本端协议、对端协议、本端端口、对端端口*/
    st->st_myuserprotoid   = c->spd.this.protocol;
    st->st_peeruserprotoid = c->spd.that.protocol;
    st->st_myuserport       = c->spd.this.port;
    st->st_peeruserport     = c->spd.that.port;

    st->st_msgid = generate_msgid(isakmp_sa);/*随机生成唯一的msgid*/
    change_state(st, STATE_QUICK_I1);/*设置当前状态为STATE_QUICK_I1*/

    insert_state(st);	/* needs cookies, connection, and msgid */

    strcpy(p2alg, "defaults");
    if(st->st_connection->alg_info_esp) {/*将alg_info_esp中的算法(第二阶段算法信息)解析转换为字符串，存储在p2alg*/
	alg_info_snprint_phase2(p2alg, sizeof(p2alg)/*只是为了显示使用*/
				, (struct alg_info_esp *)st->st_connection->alg_info_esp);
    }

    pfsgroupname="no-pfs";
    /*
     * See if pfs_group has been specified for this conn,
     * if not, fallback to old use-same-as-P1 behaviour
     */
    if (st->st_connection) {/*获取pfs组*/
	st->st_pfs_group = ike_alg_pfsgroup(st->st_connection
					    , st->st_policy);

    }

    /* If PFS specified, use the same group as during Phase 1:
     * since no negotiation is possible, we pick one that is
     * very likely supported.
     */
    if (!st->st_pfs_group)
	    st->st_pfs_group = policy & POLICY_PFS? isakmp_sa->st_oakley.group : NULL;

    if(policy & POLICY_PFS && st->st_pfs_group) {
	pfsgroupname = enum_name(&oakley_group_names, st->st_pfs_group->group);
    }

    {
	char replacestr[32];

	replacestr[0]='\0';
	if(replacing != SOS_NOBODY)
	    snprintf(replacestr, 32, " to replace #%lu", replacing);

	openswan_log("initiating Quick Mode %s%s {using isakmp#%lu msgid:%08x proposal=%s pfsgroup=%s}"
		     , prettypolicy(policy)
		     , replacestr
		     , isakmp_sa->st_serialno, st->st_msgid, p2alg, pfsgroupname);
    }

    qke = alloc_thing(struct qke_continuation , "quick_outI1 KE");
    qke->replacing = replacing;
    pcrc_init(&qke->qke_pcrc);
    qke->qke_pcrc.pcrc_func = quick_outI1_continue;/*对于KE载荷、NONCE载荷的填充是在此回调函数中实现的*/

    if(policy & POLICY_PFS) {/*生成KE载荷*/
	e=build_ke(&qke->qke_pcrc, st, st->st_pfs_group, st->st_import);
    } else {/*生成NONCE载荷*/
	e=build_nonce(&qke->qke_pcrc, st, st->st_import);
    }

    reset_globals();

    return e;
}
```

这个函数中应该注意到一点：就是**一个connection(隧道)可以对应多个state结构**。这有什么影响呢？

我们在查询隧道状态时，是通过查询该隧道(connection)对应的state来获取到协商的阶段，但是我们在遍历全局state表时只有全部遍历一遍才能查到最新的协商阶段，否则可能只是查询其中的一个state,这个可能不是最新的state。这样的话如果不采用效率高的数据结构存储状态，随着state增多，遍历的效率会很低。

**PFS（Perfect Forward Secrecy，完善的前向安全性）**是一种安全特性，指一个密钥被破解(例如说协商的第一阶段秘钥被破解)，并不影响第二阶段密钥的安全性，因为这些密钥间没有派生关系。此特性是通过在IKE第二阶段的协商中增加密钥交换来实现的，因此源码实现中，如果策略启动了PFS，则再次增加一个KE载荷进行秘钥交换。

### 4. quick_outI1_continue()源码分析

这个continue函数与之前的函数功能基本一致，通过pcrc中的状态序号获取到相应的状态，然后调用后续的函数进行报文封装操作。

```c
static void
quick_outI1_continue(struct pluto_crypto_req_cont *pcrc
		     , struct pluto_crypto_req *r
		     , err_t ugh)
{
    struct qke_continuation *qke = (struct qke_continuation *)pcrc;
    struct state *const st = state_with_serialno(qke->qke_pcrc.pcrc_serialno);/*一个效率比较低的接口*/
    stf_status e;

    DBG(DBG_CONTROLMORE
	, DBG_log("quick outI1: calculated ke+nonce, sending I1"));

    if (st == NULL) {
	loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
		__FUNCTION__);
	if (qke->md)
	    release_md(qke->md);
	return;
    }

    st->st_calculating = FALSE;

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    set_cur_state(st);	/* we must reset before exit */
    set_suspended(st, NULL);
    e = quick_outI1_tail(pcrc, r, st);
    if (e == STF_INTERNAL_ERROR)
	loglog(RC_LOG_SERIOUS, "%s: quick_outI1_tail() failed with STF_INTERNAL_ERROR", __FUNCTION__);

    reset_globals();
}

```

这个有一个需要说明的地方，`state_with_serialno`函数需要遍历全局state哈希表，虽然O(n)的时间复杂度，但是如果state结构非常多的情况下，效率很低。因此如果应用场景中可添加的隧道比较多(成百上千条)，那么需要对该接口进行优化。

`state_with_serialno()`源码实现如下：

```c
/* Find the state object with this serial number.
 * This allows state object references that don't turn into dangerous
 * dangling pointers: reference a state by its serial number.
 * Returns NULL if there is no such state.
 * If this turns out to be a significant CPU hog, it could be
 * improved to use a hash table rather than sequential seartch.
 */
struct state *
state_with_serialno(so_serial_t sn)
{
    if (sn >= SOS_FIRST)
    {
	struct state *st;
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++)
	    for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
		if (st->st_serialno == sn)
		    return st;
    }
    return NULL;
}
```



### 5. quick_outI1_tail()源码分析

quick_outI1_tail()函数的作用：构造第二阶段首包报文，他包括：

- [x] 第二阶段的加解密算法、哈希(认证)算法、PFS等策略信息
  - [ ] **构造SA建议载荷out_sa()**
- [x] 如果启动PFS，则重新进行秘钥交换，生成KE载荷
- [x] 生成Nonce载荷
- [x] 构造本端标识和对端标识载荷
- [x] NAT穿越中的 OA载荷
- [x] ==计算报文的完整性(哈希算法)==
- [x] ==对报文进行加密==

源码如下：

```c

static stf_status
quick_outI1_tail(struct pluto_crypto_req_cont *pcrc
		 , struct pluto_crypto_req *r
		 , struct state *st)
{
    struct qke_continuation *qke = (struct qke_continuation *)pcrc;
    struct state *isakmp_sa = state_with_serialno(st->st_clonedfrom);
    struct connection *c = st->st_connection;
    pb_stream rbody;
    u_char	/* set by START_HASH_PAYLOAD: */
	*r_hashval,	/* where in reply to jam hash value */
	*r_hash_start;	/* start of what is to be hashed *//*用来记录需要计算hash的起始位置*/
    bool has_client = c->spd.this.has_client || c->spd.that.has_client ||
		      	     c->spd.this.protocol    || c->spd.that.protocol   ||
		            c->spd.this.port         || c->spd.that.port;

    if(isakmp_sa == NULL) {
	/* phase1 state got deleted while cryptohelper was working */
	loglog(RC_LOG_SERIOUS,"phase2 initiation failed because parent ISAKMP #%lu is gone", st->st_clonedfrom);
	return STF_FATAL;
    }

#ifdef NAT_TRAVERSAL
    if (isakmp_sa->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {/*第一阶段协商过程中发现存在NAT设备*/
       /* Duplicate nat_traversal status in new state *//*将NAT信息存储在新的state上*/
       st->hidden_variables.st_nat_traversal = isakmp_sa->hidden_variables.st_nat_traversal;
       if (isakmp_sa->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME)) {/*本端位于NAT之后*/
 	  has_client = TRUE;
       }/*确定端口浮动后的出接口*/
       nat_traversal_change_port_lookup(NULL, st);
    }
    else {
       st->hidden_variables.st_nat_traversal = 0;
    }
#endif

    /* set up reply */
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR* out *//*填充第二阶段的ISAKMP的头部*/
    {
	struct isakmp_hdr hdr;

	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_QUICK;
	hdr.isa_msgid = st->st_msgid;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream, &rbody))/*填充到报文中*/
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }
   /*填充hash载荷头部，数据部分全零，并记录下要填充hash的位置，最后填充*/
    /* HASH(1) -- create and note space to be filled later */
    START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_SA);

    /* SA out */

    /* Emit SA payload based on a subset of the policy bits.
     * POLICY_COMPRESS is considered iff we can do IPcomp.
     */
    {
        lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

        if (can_do_IPcomp)
            pm |= POLICY_COMPRESS;
    /*填充sa载荷: ESP AH IPCom*/
        if (!out_sa(&rbody
                , &ipsec_sadb[(st->st_policy & pm) >> POLICY_IPSEC_SHIFT]
                , st, FALSE, FALSE, ISAKMP_NEXT_NONCE))
        {
            reset_cur_state();
            return STF_INTERNAL_ERROR;
        }
    }

    {
        int np;

        if(st->st_policy & POLICY_PFS) {/*如果使用PFS,则需要再次DH协商*/
            np = ISAKMP_NEXT_KE;
        } else {
            if(has_client) {
            np = ISAKMP_NEXT_ID;
            } else {
            np = ISAKMP_NEXT_NONE;
            }
        }

        /* Ni out *//*填充Nonce载荷，并将其存储在st_ni中*/
        if (!ship_nonce(&st->st_ni, r, &rbody
                , np
                , "Ni"))
            {
            reset_cur_state();
            return STF_INTERNAL_ERROR;
            }
        }

        /* [ KE ] out (for PFS) *//*填充KE载荷，并将其存储在st_gi*/
        if (st->st_pfs_group != NULL)
        {
            if (!ship_KE(st, r, &st->st_gi
                     , &rbody
                     , has_client? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE))
            {
                reset_cur_state();
                return STF_INTERNAL_ERROR;
            }
        }

        /* [ IDci, IDcr ] out */
        if (has_client)/*填充的子网ID*/
        {
            /* IDci (we are initiator), then IDcr (peer is responder) */
            if (!emit_subnet_id(&c->spd.this/*本端身份标识*/
                        , ISAKMP_NEXT_ID
                                    , st->st_localaddr
                        , st->st_myuserprotoid
                        , st->st_myuserport, &rbody)
                || !emit_subnet_id(&c->spd.that/*对端身份标识*/
                           , ISAKMP_NEXT_NONE
                                       , st->st_remoteaddr
                           , st->st_peeruserprotoid
                           , st->st_peeruserport, &rbody))
            {
                reset_cur_state();
                return STF_INTERNAL_ERROR;
            }
        }

#ifdef NAT_TRAVERSAL
    if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA)
	&& (!(st->st_policy & POLICY_TUNNEL))/*只有传输模式才需要OA载荷????*/
	&& (st->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME))) {
    /** Send NAT-OA if our address is NATed *//*填充OA载荷，这里需要修改上一个载荷的NP*/
        if (!nat_traversal_add_natoa(ISAKMP_NEXT_NONE, &rbody, st, TRUE /* initiator */)) {
            reset_cur_state();
            return STF_INTERNAL_ERROR;
        }
    }
#endif

#ifdef TPM
    {
	pb_stream *pbs = &rbody;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash",st,pbs,sizeof(struct isakmp_hdr),enc_len);
	r_hashval = tpm_relocateHash(pbs);
    }
#endif

    /* finish computing  HASH(1), inserting it in output *//*计算整个载荷的哈希值*/
    (void) quick_mode_hash12(r_hashval, r_hash_start, rbody.cur
	, st, &st->st_msgid, FALSE);

    /* encrypt message, except for fixed part of header */
/*设置第二阶段的IV值*/
	
    init_phase2_iv(isakmp_sa, &st->st_msgid);
    st->st_new_iv_len = isakmp_sa->st_new_iv_len;
    set_new_iv(st, isakmp_sa->st_new_iv);

    if (!encrypt_message(&rbody, st))/*加密除报文头部以外的所有载荷*/
    {
	reset_cur_state();
	return STF_INTERNAL_ERROR;
    }

    /* save packet, now that we know its size 保留数据包，超时重传会使用到*/
    clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
	, "reply packet from quick_outI1");

    /* send the packet */
    /*发送报文，如果使用了NAT-T,则会添加Non-ESP的封装*/
    send_packet(st, "quick_outI1", TRUE);

    delete_event(st);/*设置超时重传事件*/
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    if (qke->replacing == SOS_NOBODY)
	whack_log(RC_NEW_STATE + STATE_QUICK_I1
	    , "%s: initiate"
	    , enum_name(&state_names, st->st_state));
    else
	whack_log(RC_NEW_STATE + STATE_QUICK_I1
	    , "%s: initiate to replace #%lu"
	    , enum_name(&state_names, st->st_state)
	    , qke->replacing);

    return STF_OK;
}

```

-----

下面对`quick_outI1_tail()`中的几个重要函数做个简单说明：

#### 5.1 out_sa()

这个函数在第一阶段的前两个报文中使用过，当时使用的第一阶段的SA载荷，现在使用第二阶段的SA载荷；`out_sa`同时实现了第一阶段和第二阶段SA载荷封装的功能，它通过`bool oakley_mode`参数来确定使用第一阶段还是第二阶段的封装流程。如果说`out_struct`等封装接口已经比较熟的话，那么这个函数可能会比较容易，否则基本流程看起来还是有点吃力。这里只简单说明`out_struct`各个参数的作用：

```c
/****************************************************************
将struct_ptr按照sd的描述方式拷贝到outs中。同时如果obj_pbs存在，
则使obj_pbs指向outs数据部分，并更新obj_pbs的cur指针到新填充的位置，
然后将outs的cur设置到最大，其他函数不得再操作outs,除非使用close_output_pbs更新才行
****************************************************************/
bool
out_struct(const void *struct_ptr, struct_desc *sd, pb_stream *outs, pb_stream *obj_pbs)
```

openswan源码在对齐上做的不敢恭维，而代码是不忍卒读(看不懂![img](F:%5C%E9%9A%8F%E7%AC%94%5Copenswan%5C%E5%BF%AB%E9%80%9F%E6%A8%A1%E5%BC%8F%E7%AC%AC%E4%B8%80%E5%8C%85%EF%BC%9Aquick_outI1.assets%5C433F992D.gif))。

```c
bool
out_sa(pb_stream *outs
       , struct db_sa *sadb
       , struct state *st
       , bool oakley_mode
       , bool aggressive_mode UNUSED
       , u_int8_t np)
{
    pb_stream sa_pbs;
    unsigned int pcn;
    bool ret = FALSE;
    bool ah_spi_generated = FALSE
          , esp_spi_generated = FALSE
          , ipcomp_cpi_generated = FALSE;
    struct db_sa *revised_sadb;


    if(oakley_mode) {
/* Aggr-Mode - Max transforms == 2 - Multiple transforms, 1 DH group */
/*根据配置的秘钥算法信息重新生成一个sadb信息*/
/*传入的sadb应该为固定的秘钥算法信息，因此需要根据策略来重新生成一个新的sadb*/
      revised_sadb = oakley_alg_makedb(st->st_connection->alg_info_ike/*第一阶段算法*/
                                               , sadb
                                               , aggressive_mode ? 2 : -1);
    } else {/*根据配置生成第二阶段的算法信息*/
      revised_sad = kernel_alg_makedb(st->st_connection->policy
                   , st->st_connection->alg_info_esp/*第二阶段算法*/
                   , TRUE);
		/*IPComp代码略*/
    }

    /* more sanity */
    if(revised_sadb != NULL) {
          sadb = revised_sadb;
    }

    /* SA header out */
    {/*添加SA头部*/
/*                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                           Situation                           ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
          struct isakmp_sa sa;

          sa.isasa_np = np;
          st->st_doi = sa.isasa_doi = ISAKMP_DOI_IPSEC; /* all we know */
          if (!out_struct(&sa, &isakmp_sa_desc, outs, &sa_pbs))
              return_on(ret, FALSE);
    }

    /* within SA: situation out *//*填充上图中的Situation字段*/
    st->st_situation = SIT_IDENTITY_ONLY;
    if (!out_struct(&st->st_situation, &ipsec_sit_desc, &sa_pbs, NULL))
          return_on(ret, FALSE);

    /* within SA: Proposal Payloads   建议载荷
     *
     * Multiple Proposals with the same number are simultaneous
     * (conjuncts) and must deal with different protocols (AH or ESP).
     * Proposals with different numbers are alternatives (disjuncts),
     * in preference order.
     * Proposal numbers must be monotonic.
     * See RFC 2408 "ISAKMP" 4.2
     */

    for (pcn = 0; pcn < sadb->prop_conj_cnt; pcn++)
    {
          struct db_prop_conj *pc;
          unsigned int pn;
          int valid_prop_cnt;

          pc = &sadb->prop_conjs[pcn];/*遍历建议载荷*/
          valid_prop_cnt = pc->prop_cnt;
          DBG(DBG_EMITTING,
              DBG_log("out_sa pcn: %d has %d valid proposals",
                        pcn, valid_prop_cnt));

          for (pn = 0; pn < pc->prop_cnt; pn++)/*遍历建议载荷*/
          {
              struct db_prop *p;
              pb_stream proposal_pbs;
              struct isakmp_proposal proposal;
              struct_desc *trans_desc;
              struct_desc *attr_desc;
              enum_names **attr_val_descs;
              unsigned int tn;
              bool tunnel_mode;

              /*
               * set the tunnel_mode bit on the last proposal only, and
               * only if we are trying to negotiate tunnel mode in the first
               * place.
               */
              tunnel_mode = (valid_prop_cnt == 1)
                    && (st->st_policy & POLICY_TUNNEL);

              /*
        * pick the part of the proposal we are trying to work on
        */
		 /*                      1                   2                   3
		 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * ! Next Payload  !   RESERVED    !         Payload Length        !
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * !  Proposal #   !  Protocol-Id  !    SPI Size   !# of Transforms!
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * !                        SPI (variable)                         !
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
			  
              p = &pc->props[pn];

              proposal.isap_proposal = pcn;
              proposal.isap_protoid = p->protoid;
              proposal.isap_spisize = oakley_mode ? 0
                    : p->protoid == PROTO_IPCOMP ? IPCOMP_CPI_SIZE
                    : IPSEC_DOI_SPI_SIZE;


              /* but, skip things if the transform count is zero */
              if(p->trans_cnt == 0) continue;

              /* Proposal header */
              if(--valid_prop_cnt > 0) {
                    proposal.isap_np = ISAKMP_NEXT_P;
              } else {
                    proposal.isap_np = ISAKMP_NEXT_NONE;
              }

              proposal.isap_notrans = p->trans_cnt;/*变换载荷的个数*/
              if (!out_struct(&proposal, &isakmp_proposal_desc
                                  , &sa_pbs, &proposal_pbs))
                    return_on(ret, FALSE);

       /* Per-protocols stuff:
       * Set trans_desc.
       * Set attr_desc.
       * Set attr_val_descs.
       * If not oakley_mode, emit SPI.
       * We allocate SPIs on demand.
       * All ESPs in an SA will share a single SPI.
       * All AHs in an SAwill share a single SPI.
       * AHs' SPI will be distinct from ESPs'.
       * This latter is needed because KLIPS doesn't
       * use the protocol when looking up a (dest, protocol, spi).
       * ??? If multiple ESPs are composed, how should their SPIs
       * be allocated?
       */
       {
		  struct ipsec_proto_info *pi = NULL;
		  int proto = 0;
		  bool *spi_generated;

                    spi_generated = NULL;

                    switch (p->protoid)
                    {
	                    case PROTO_ISAKMP:
	                        passert(oakley_mode);
	                        trans_desc = &isakmp_isakmp_transform_desc;
	                        attr_desc = &isakmp_oakley_attribute_desc;
	                        attr_val_descs = oakley_attr_val_descs;
	                        /* no SPI needed */
	                        break;
	/*第二阶段时，在kernel_alg_db_new中根据策略配置选择采用的封装方式*/
	                    case PROTO_IPSEC_AH:
	                        passert(!oakley_mode);
	                        trans_desc = &isakmp_ah_transform_desc;
	                        attr_desc = &isakmp_ipsec_attribute_desc;
	                        attr_val_descs = ipsec_attr_val_descs;
				pi = &st->st_ah;
	                        spi_generated = &ah_spi_generated;
	                        proto = IPPROTO_AH;
	                        break;

	                    case PROTO_IPSEC_ESP:
	                        passert(!oakley_mode);
	                        trans_desc = &isakmp_esp_transform_desc;
	                        attr_desc = &isakmp_ipsec_attribute_desc;
	                        attr_val_descs = ipsec_attr_val_descs;
				pi = &st->st_esp;
	                        spi_generated = &esp_spi_generated;
	                        proto = IPPROTO_ESP;
	                        break;

	                    case PROTO_IPCOMP:
	                        passert(!oakley_mode);
	                        trans_desc = &isakmp_ipcomp_transform_desc;
	                        attr_desc = &isakmp_ipsec_attribute_desc;
	                        attr_val_descs = ipsec_attr_val_descs;

	                        /* a CPI isn't quite the same as an SPI
	                         * so we use specialized code to emit it.
	                         */
	                        if (!ipcomp_cpi_generated)
	                        {
	                              st->st_ipcomp.our_spi = get_my_cpi(st, tunnel_mode);
	                              if (st->st_ipcomp.our_spi == 0)
	                                  return_on(ret, FALSE);          /* problem generating CPI */

	                              ipcomp_cpi_generated = TRUE;
	                        }
	                        /* CPI is stored in network low order end of an
	                         * ipsec_spi_t.  So we start a couple of bytes in.
	                         */
	                        if (!out_raw((u_char *)&st->st_ipcomp.our_spi
	                         + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
	                        , IPCOMP_CPI_SIZE
	                        , &proposal_pbs, "CPI"))
	                              return_on(ret, FALSE);
	                        break;

	                    default:
	                        bad_case(p->protoid);
                    }

                    if (pi != NULL)
                    {
	                        if (spi_generated != NULL && !*spi_generated)
	                        {
					    if (!get_ipsec_spi(pi
							       , proto
							       , st
							       , tunnel_mode)) {
						return FALSE;
					    }
					    *spi_generated = TRUE;
	                        }
	                        if (!out_raw((u_char *)&pi->our_spi, IPSEC_DOI_SPI_SIZE
					     , &proposal_pbs, "SPI"))
				    	return_on(ret, FALSE);
                    }
              }

              /* 填充变换载荷 within proposal: Transform Payloads */
              for (tn = 0; tn != p->trans_cnt; tn++)
              {
                    struct db_trans *t = &p->trans[tn];
                    pb_stream trans_pbs;
                    struct isakmp_transform trans;
                    unsigned int an;

                    trans.isat_np = (tn == p->trans_cnt - 1)
                        ? ISAKMP_NEXT_NONE : ISAKMP_NEXT_T;
                    trans.isat_transnum = tn;
                    trans.isat_transid = t->transid;
                    if (!out_struct(&trans, trans_desc, &proposal_pbs, &trans_pbs))
                        return_on(ret, FALSE);

                    /* Within tranform: Attributes. */

                    /* For Phase 2 / Quick Mode, GROUP_DESCRIPTION is
                     * automatically generated because it must be the same
                     * in every transform.  Except IPCOMP.
                     */
                    if (p->protoid != PROTO_IPCOMP
                    && st->st_pfs_group != NULL)/*添加PFS组属性信息*/
                    {
                        passert(!oakley_mode);
                        passert(st->st_pfs_group != &unset_group);
                        out_attr(GROUP_DESCRIPTION, st->st_pfs_group->group
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
                    }

                    /* automatically generate duration
                     * and, for Phase 2 / Quick Mode, encapsulation.
                     */
                    if (oakley_mode)/*第一阶段*/
                    {
                        out_attr(OAKLEY_LIFE_TYPE, OAKLEY_LIFE_SECONDS
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
                        out_attr(OAKLEY_LIFE_DURATION
                              , st->st_connection->sa_ike_life_seconds
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
                    }
                    else/*第二阶段*/
                    {
                        /* RFC 2407 (IPSEC DOI) 4.5 specifies that
                         * the default is "unspecified (host-dependent)".
                         * This makes little sense, so we always specify it.
                         *
                         * Unlike other IPSEC transforms, IPCOMP defaults
                         * to Transport Mode, so we can exploit the default
                         * (draft-shacham-ippcp-rfc2393bis-05.txt 4.1).
                         */
                        if (p->protoid != PROTO_IPCOMP
                        || st->st_policy & POLICY_TUNNEL)
                        {
							/*隧道模式? 传输模式*/
                            out_attr(ENCAPSULATION_MODE
#ifdef NAT_TRAVERSAL
#ifdef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
                                  , NAT_T_ENCAPSULATION_MODE(st,st->st_policy)
#else
                          /* If NAT-T is detected, use UDP_TUNNEL as long as Transport
                           * Mode has security concerns.
                           *
                           * User has been informed of that
                           */
                                  , NAT_T_ENCAPSULATION_MODE(st,POLICY_TUNNEL)
#endif
#else /* ! NAT_TRAVERSAL */
                                  , st->st_policy & POLICY_TUNNEL
                                    ? ENCAPSULATION_MODE_TUNNEL : 			ENCAPSULATION_MODE_TRANSPORT
#endif
                                  , attr_desc, attr_val_descs
                                  , &trans_pbs);
                        }
                        out_attr(SA_LIFE_TYPE, SA_LIFE_TYPE_SECONDS /*单位:秒*/ 
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
                        out_attr(SA_LIFE_DURATION
                              , st->st_connection->sa_ipsec_life_seconds /*生存时间从连接上获取*/
                              , attr_desc, attr_val_descs
                              , &trans_pbs);

                    }

                    /* spit out attributes from table */
                    for (an = 0; an != t->attr_cnt; an++)
                    {
                        struct db_attr *a = &t->attrs[an];

                        if(oakley_mode) {
                              out_attr(a->type.oakley, a->val
                                         , attr_desc, attr_val_descs
                                         , &trans_pbs);
                        } else {
                           out_attr(a->type.ipsec,  a->val , attr_desc, attr_val_descs , &trans_pbs);

                        }

                    }

                    close_output_pbs(&trans_pbs);
              }
              close_output_pbs(&proposal_pbs);
          }
          /* end of a conjunction of proposals */
    }
    close_output_pbs(&sa_pbs);
    ret = TRUE;

return_out:

#if defined(KERNEL_ALG) || defined(IKE_ALG)
    if (revised_sadb)
          free_sa(revised_sadb);
#endif
    return ret;
}

```

一般而言，比较关心我们配置的参数在哪里生效？ 例如加密算法、认证算法、隧道模式or传输模式都是在`out_sa()`中通过属性载荷封装在报文中的。下图为属性载荷结构：

![image-20200827002952001](F:%5C%E9%9A%8F%E7%AC%94%5Copenswan%5C%E5%BF%AB%E9%80%9F%E6%A8%A1%E5%BC%8F%E7%AC%AC%E4%B8%80%E5%8C%85%EF%BC%9Aquick_outI1.assets%5Cimage-20200827002952001.png)

属性类型的最高比特位AF指定数据为定长还是变长，如果为0表示定长；如果为1表示变长。

具体属性类型有以下几种（全是定长类型）：

| 属性类型     | 属性类型取值 | 属性值说明                                        |
| ------------ | ------------ | ------------------------------------------------- |
| SA生存周期   | 1            | 0: 保留    1:秒    2:千字节                       |
| SA生存期     | 2            | 0: 保留    1:秒    2:千字节                       |
| 组描述       | 3            | 略                                                |
| **封装模式** | 4            | 0：保留     1：隧道模式      2：传输模式          |
| **认证算法** | 5            | 0：RESERVED    1：HMAC-MD5      2:HMAC-SHA   .... |
| 密钥长度     | 6            | 略                                                |
| 密钥轮数     | 7            | 略                                                |
| 压缩字典长度 | 8            | 略                                                |
| 私有压缩算法 | 9            | 略                                                |

注：加密算法不适用属性载荷进行封装。



#### 5.2 emit_subnet_id()

第二阶段除了协商加解密算法信息，还会对双方的保护子网进行匹配。而保护子网是通过ID载荷来传输的。在第一阶段中使用`build_id_payload()`接口将我们在配置隧道的“**身份标识**”发送对方以供双方认证，第二阶段使用`emit_subnet_id()`来协商两端的保护子网信息。

每一条隧道有本端和对端两个节点，这两个节点都是用`struct end`结构描述，而两端的保护子网使用`struct end`中的`ip_subnet client;`描述，`ip_subnet`结构如下：

```c
typedef struct {
	ip_address addr;
	int maskbits;
} ip_subnet;
```



```c
/* Initiate quick mode.
 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Note: this is not called from demux.c
 */
/*填充的是隧道端口IP还是子网的信息? 
*保护子网是如何协商的???
*/
static bool
emit_subnet_id(struct end *e
	       , u_int8_t np
               , ip_address endpoint
	       , u_int8_t protoid
	       , u_int16_t port
	       , pb_stream *outs)
{
    struct isakmp_ipsec_id id;
    pb_stream id_pbs;
    ip_address ta;
    unsigned char *tbp;
    size_t tal;
    const struct af_info *ai;
    bool usehost = FALSE;
    ip_subnet clientnet;

    clientnet = e->client;

    if(!e->has_client) {
        /* we propose the IP address of the interface that we are using. */
        /*
     * we could instead propose 0.0.0.0->255.255.255.255 and let the other
     * end narrow the TS, but if one wants that, it is easy to just specify
     * in the configuration file: rightsubnet=0.0.0.0/0.
     *
     * When there is NAT involved, we may really want a tunnel to the
     * address that this end point thinks it is.  That works only when
     * virtual_ip includes the IP involved.
     *
     */
        addrtosubnet(&endpoint, &clientnet);
    }

    ai = aftoinfo(subnettypeof(&clientnet));
    passert(ai != NULL);

    id.isaiid_np = np;
    id.isaiid_idtype = (usehost ? ai->id_addr : ai->id_subnet);/*确定使用主机ID还是子网ID；由于usehost===FALSE,因此这里使用子网ID*/
    id.isaiid_protoid = protoid;
    id.isaiid_port = port;

    if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_pbs))
	return FALSE;

    networkof(&clientnet, &ta);/*获取保护子网*/
    tal = addrbytesptr(&ta, &tbp);
    if (!out_raw(tbp, tal, &id_pbs, "client network"))/*填充保护子网信息*/
	return FALSE;

    if(!usehost)
    {
	maskof(&clientnet, &ta);/*获取保护子网掩码*/
	tal = addrbytesptr(&ta, &tbp);
	if (!out_raw(tbp, tal, &id_pbs, "client mask"))/*填充保护子网掩码信息*/
	    return FALSE;
    }

    close_output_pbs(&id_pbs);
    return TRUE;
}

```

ID载荷(标识载荷)包含以下几种类型：

| ID类型                  | 描述                                          | 取值         |
| ----------------------- | --------------------------------------------- | ------------ |
| ID_NONE                 | 未使用                                        | 0            |
| **ID_IPV4_ADDR**        | 单独的一个IPv4地址                            | 1            |
| **ID_FQDN**             | 全域名字符串，如topsec.com.cn                 | 2            |
| **ID_USER_FQDN**        | 用户名字符串，如li_si@topsec.com.cn           | 3            |
| ID_RFC822_ADDR          | 同ID_USER_FQDN                                | ID_USER_FQDN |
| **ID_IPV4_ADDR_SUBNET** | IPv4类子网地址，如192.168.1.1 255.255.255.0   | 4            |
| ID_IPV6_ADDR            | 单独IPv6地址                                  | 5            |
| ID_IPV6_ADDR_SUBNET     | IPv6子网地址                                  | 6            |
| ID_IPV4_ADDR_RANGE      | IPv4地址范围区间, 如192.168.2.3 192.168.2.200 | 7            |
| ID_IPV6_ADDR_RANGE      | IPv6地址范围区间                              | 8            |
| ID_DER_ASN1_DN          | x.500编码格式                                 | 9            |
| ID_DER_ASN1_GN          | x.500编码格式                                 | 10           |
| ID_KEY_ID               | 传递特定厂商信息的字节流                      | 11           |

#### 5.3 encrypt_message()

报文的加密范围：除了ISAKMP头部之外都需要进行加密。加密使用第一阶段协商的加密秘钥（报文认证时同时也会用到认证密钥）。

```c
/* encrypt message, sans fixed part of header
 * IV is fetched from st->st_new_iv and stored into st->st_iv.
 * The theory is that there will be no "backing out", so we commit to IV.
 * We also close the pbs.
 */
bool
encrypt_message(pb_stream *pbs, struct state *st)
{
    const struct encrypt_desc *e = st->st_oakley.encrypter;
    u_int8_t *enc_start = pbs->start + sizeof(struct isakmp_hdr);/*加密的内容为ISAKMP头部之后*/
    size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);/*加密内容的长度*/

    DBG_cond_dump(DBG_CRYPT | DBG_RAW, "encrypting:\n", enc_start, enc_len);
    DBG_cond_dump(DBG_CRYPT | DBG_RAW, "IV:\n"
		  , st->st_new_iv
		  , st->st_new_iv_len);
    DBG(DBG_CRYPT, DBG_log("unpadded size is: %u", (unsigned int)enc_len));

    /* Pad up to multiple of encryption blocksize.
     * See the description associated with the definition of
     * struct isakmp_hdr in packet.h.
     */
    {
    /*确定需要填充的长度*/
	size_t padding = pad_up(enc_len, e->enc_blocksize);

	if (padding != 0)/*如果填充的长度不为0,则需要进行填充数据*/
	{
	    if (!out_zero(padding, pbs, "encryption padding"))/*在输出流上进行报文填充*/
		return FALSE;
	    enc_len += padding;
	}
    }

    DBG(DBG_CRYPT
	, DBG_log("encrypting %d using %s"
		  , (unsigned int)enc_len
		  , enum_show(&oakley_enc_names, st->st_oakley.encrypt)));

    TCLCALLOUT_crypt("preEncrypt", st, pbs,sizeof(struct isakmp_hdr),enc_len);/*非TPM未做任何处理*/

    /* e->crypt(TRUE, enc_start, enc_len, st); */
    crypto_cbc_encrypt(e, TRUE, enc_start, enc_len, st);/*使用CBC算法进行加密:使用连接上第一阶段协商的加密算法和加密密钥信息*/

    TCLCALLOUT_crypt("postEncrypt", st,pbs,sizeof(struct isakmp_hdr),enc_len);

    update_iv(st);
    DBG_cond_dump(DBG_CRYPT, "next IV:", st->st_iv, st->st_iv_len);
    close_message(pbs);
    return TRUE;
}
```

#### 5.4 out_modify_previous_np()

此函数的作用在于修改前一个载荷头部中的下一个载荷字段。它在填充NAT-T相关的OA载荷时用到。基本原理是从头部开始向后遍历每一个载荷，直到找到最后一个载荷的头部(尚未填充新的载荷，因此它还是最后一个载荷)。

```c
bool
out_modify_previous_np(u_int8_t np, pb_stream *outs)
{
    u_int8_t *pl = outs->start;
    size_t left = outs->cur - outs->start;

    passert(left >= NSIZEOF_isakmp_hdr);    /* not even room for isakmp_hdr! */
    if (left == NSIZEOF_isakmp_hdr) {
	/* no payloads, just the isakmp_hdr: insert np here */
	passert(pl[NOFFSETOF_isa_np] == ISAKMP_NEXT_NONE ||
		pl[NOFFSETOF_isa_np] == ISAKMP_NEXT_HASH);
	pl[NOFFSETOF_isa_np] = np;
    } else {
	pl += NSIZEOF_isakmp_hdr;       /* skip over isakmp_hdr */
	left -= NSIZEOF_isakmp_hdr;
	for (;;) {
		size_t pllen;

		passert(left >= NSIZEOF_isakmp_generic);
		pllen = (pl[NOFFSETOF_isag_length] << 8)/*payload 一般为两个字节*/
			| pl[NOFFSETOF_isag_length + 1];
		passert(left >= pllen);
		if (left == pllen) {/*当前载荷长度和剩余长度相同时，说明已经找到上一个载荷*/
			/* found last top-level payload */
			pl[NOFFSETOF_isag_np] = np;
			break;  /* done */
		} else {
			/* this payload is not the last: scan forward */
			pl += pllen;
			left -= pllen;
		}
	}
	}
	return TRUE;
}
```

### 6. 小结

略