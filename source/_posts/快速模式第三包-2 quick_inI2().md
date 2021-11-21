---
title: 快速模式第三包收尾之quick_inI2()
date: 2021-11-20 21:28:38
tags: 
- IPSec
- openswan
- VPN
categories: 
- IPSecVPN
- openswan
---

![image-20200913162318278](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205321.png)

<!--more-->
### 1. 序言

快速模式有三个报文交换，四个核心函数入口。我们已经对前三个函数处理流程对了一个简单的学习和这里，下面对第四个函数入口`quick_inI2()`的处理流程做一个简单的介绍。

首先需要说明的是快速模式的前两个报文是为了协商感兴趣流的相关参数(如使用的加密算法、认证算法、封装方式、感兴趣流以及生成相关的密钥信息等)，而第三个报文则简单了很多：只是为了对前两个报文做认证。那么自然而然引出一个问题：为什么需要第三个报文呢？前两个报文不是已经包含HASH杂凑载荷吗？ 供大家思考吧。

### 2.  quick_inI2()处理流程图

`quick_inI2()`的处理流程很简单，其中最主要的便是建立出站IPsecSA。（如果IPsec处理流程都是这种精简的，该多好呀:) :) ）

![image-20200913164700196](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205604.png)

### 3.  报文格式

`quick_inR1_outI2()`和`quick_inI2()`都是用来处理快速模式最后一个包的，报文格式完全一致。，`quick_inR1_outI2()`包括发送处理流程，而`quick_inI2()`则只为处理接收流程。

![图片1](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205602.png)

### 4.  quick_inI2()源码

这个源码主要流程很清晰（除了建立IPsecSA），代码也很少。

```c
/* Handle last message of Quick Mode.
 * HDR*, HASH(3) -> done
 * (see RFC 2409 "IKE" 5.5)
 * Installs outbound IPsec SAs, routing, etc.
 */
stf_status
quick_inI2(struct msg_digest *md)
{
    struct state *const st = md->st;

    /* HASH(3) in *//*验证哈希报文完整性*/
    CHECK_QUICK_HASH(md, quick_mode_hash3(hash_val, st)
	, "HASH(3)", "Quick I2");

    /* Tell the kernel to establish the outbound and routing part of the new SA
     * (the previous state established inbound)
     * (unless the commit bit is set -- which we don't support).
     * We do this before any state updating so that
     * failure won't look like success.
     */
    if (!install_ipsec_sa(md->pst, st, FALSE))
	return STF_INTERNAL_ERROR;

    {
      DBG(DBG_CONTROLMORE, DBG_log("inI2: instance %s[%ld], setting newest_ipsec_sa to #%ld (was #%ld) (spd.eroute=#%ld)"
			       , st->st_connection->name
			       , st->st_connection->instance_serial
			       , st->st_serialno
			       , st->st_connection->newest_ipsec_sa
			       , st->st_connection->spd.eroute_owner));
    }

    st->st_connection->newest_ipsec_sa = st->st_serialno;

    update_iv(st);	/* not actually used, but tidy */

    /* note (presumed) success */
    {
	struct gw_info *gw = st->st_connection->gw_info;

	if (gw != NULL)
	    gw->key->last_worked_time = now();
    }

    /* If we have dpd delay and dpdtimeout set, then we are doing DPD
	on this conn, so initialize it */
    if(st->st_connection->dpd_delay && st->st_connection->dpd_timeout) {
	if(dpd_init(st) != STF_OK) {
	    delete_ipsec_sa(st, FALSE);
	    return STF_FAIL;
	}
    }

    return STF_OK;
}
```





### 4.  其他接口说明

#### 4.1  hash载荷计算方式

快速模式虽然仅有三个报文交互，但是它们的hash杂凑载荷的计算方式却不相同：

- [x] 第①包计算方式：
  $$
  HASH(1) = PRF(SKEYID-a, MsgID | SA | Ni | [| IDi | IDr ])
  $$
  
- [x] 第②包计算方式：
  $$
  HASH(2) = PRF(SKEYID-a, MsgID | Ni | SA | Nr |      [| IDi | IDr ])
  $$
  
- [x] 第③包计算方式：

$$
HASH(3) = PRF(SKEYID-a, 0 | MsgID | Ni | Nr)
$$

---



- 第①包实现方式和第②包实现方式为同一个函数：

  ```c
  /* Compute HASH(1), HASH(2) of Quick Mode.
   * HASH(1) is part of Quick I1 message.
   * HASH(2) is part of Quick R1 message.
   * Used by: quick_outI1, quick_inI1_outR1 (twice), quick_inR1_outI2
   * (see RFC 2409 "IKE" 5.5, pg. 18 or draft-ietf-ipsec-ike-01.txt 6.2 pg 25)
   */
  size_t
  quick_mode_hash12(u_char *dest, const u_char *start, const u_char *roof
  , const struct state *st, const msgid_t *msgid, bool hash2)
  {
      struct hmac_ctx ctx;
  
      hmac_init_chunk(&ctx, st->st_oakley.prf_hasher, st->st_skeyid_a);/*PRF算法 + 认证秘钥*/
      
      hmac_update(&ctx, (const void *) msgid, sizeof(msgid_t));/*填充msgid，由于认证需要msgid，而它唯一*/
      
      if (hash2)
  		hmac_update_chunk(&ctx, st->st_ni);	/* include Ni_b in the hash */
      
      hmac_update(&ctx, start, roof-start);/*数据起始位置和终止位置*/
      hmac_final(dest, &ctx);
  
      return ctx.hmac_digest_len;
  }
  ```

- 第③包实现方式：

```c
/* Compute HASH(3) in Quick Mode (part of Quick I2 message).
 * Used by: quick_inR1_outI2, quick_inI2
 * See RFC2409 "The Internet Key Exchange (IKE)" 5.5.
 * NOTE: this hash (unlike HASH(1) and HASH(2)) ONLY covers the
 * Message ID and Nonces.  This is a mistake.
 */
static size_t
quick_mode_hash3(u_char *dest, struct state *st)/*第二阶段的三个报文hash值算法方式各不相同*/
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.prf_hasher, st->st_skeyid_a);
    hmac_update(&ctx, (const u_char *)"\0", 1);
    hmac_update(&ctx, (u_char *) &st->st_msgid, sizeof(st->st_msgid));
    hmac_update_chunk(&ctx, st->st_ni);
    hmac_update_chunk(&ctx, st->st_nr);
    hmac_final(dest, &ctx);
    DBG_cond_dump(DBG_CRYPT, "HASH(3) computed:", dest, ctx.hmac_digest_len);
    return ctx.hmac_digest_len;
}
```

#### 4.2  install_ipsec_sa

<img src="https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205609.gif" alt="timg22" style="zoom:50%;" />

### 5. 小结

![img](https://raw.githubusercontent.com/Top-Fish/PhotoRepository/main/img/SSL-TLS/20211120205624.jpg)



IPsec协商流程之主模式+快速模式学习跨度比较久（3个月多），协商流程却是很复杂，而且只是看原理性知识，很多功能都没有敢去涉及，如证书认证、out_sa、 DPD、建立IPsecSA、NAT-T等等。学习期间最主要的体会是：openswan封装了很多很多接口，常用接口需要好好学习，否则在看代码时很困难。就拿`out_sa` 、`out_struct`、`out_generic`等系列，能恶心死人，全文基本都用这几个接口在封装报文和解封装报文，可以说这些基本函数是看openswan源码的接口。

后面计划继续更新几个函数接口实现，也是以前学习整理过程中遗留的坑，先填几个然后在更新学习其他流程。





