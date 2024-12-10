/*
MIT License

Copyright (c) 2021 sflow

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> // for PRIu64 etc.
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/psample.h>
#include <net/if.h>
#include <signal.h>
#include <ctype.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#define PST_PSAMPLE_READNL_RCV_BUF 8192
#define PST_PSAMPLE_READNL_BATCH 100
#define PST_PSAMPLE_RCVBUF 8000000

#define PST_SHORT_CIRCUIT_TEST 1
#define PST_LISTEN_MODE 1
  
  typedef uint32_t bool;
#define YES ((bool)1)
#define NO ((bool)0)
  
  // Shadow the attributes in linux/psample.h so
  // we can easily compile/test fields that are not
  // defined on the kernel we are compiling on.
  typedef enum {
    /* sampled packet metadata */
    PST_PSAMPLE_ATTR_IIFINDEX,
    PST_PSAMPLE_ATTR_OIFINDEX,
    PST_PSAMPLE_ATTR_ORIGSIZE,
    PST_PSAMPLE_ATTR_SAMPLE_GROUP,
    PST_PSAMPLE_ATTR_GROUP_SEQ,
    PST_PSAMPLE_ATTR_SAMPLE_RATE,
    PST_PSAMPLE_ATTR_DATA,
    PST_PSAMPLE_ATTR_TUNNEL,

    /* commands attributes */
    PST_PSAMPLE_ATTR_GROUP_REFCOUNT,

    PST_PSAMPLE_ATTR_PAD,
    PST_PSAMPLE_ATTR_OUT_TC,/* u16 */
    PST_PSAMPLE_ATTR_OUT_TC_OCC,/* u64, bytes */
    PST_PSAMPLE_ATTR_LATENCY,/* u64, nanoseconds */
    PST_PSAMPLE_ATTR_TIMESTAMP,/* u64, nanoseconds */
    PST_PSAMPLE_ATTR_PROTO,/* u16 */

    __PST_PSAMPLE_ATTR_MAX
  } EnumPSTAttributes;
  
  typedef struct _PST {
    uint32_t id;
    int nl_sock;
    uint32_t nl_seq;
    uint32_t genetlink_version;
    uint16_t family_id;
    uint32_t group_id;
  } PST;

  typedef struct _PSAttr {
    bool included:1;
    bool onheap:1;
    struct nlattr attr;
    struct iovec val;
    uint64_t buf64;
  } PSAttr;
    
  typedef struct _PSSpec {
    struct nlmsghdr nlh;
    struct genlmsghdr ge;
    PSAttr attr[__PST_PSAMPLE_ATTR_MAX];
    int n_attrs;
    int attrs_len;
  } PSSpec;


  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

#define LOGPREFIX "pstest: "

  void myLogv(char *fmt, va_list args) {
    fprintf(stdout, LOGPREFIX);
    vfprintf(stdout, fmt, args);
  }

  void myLog(char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    myLogv(fmt, args);
  }

  /*________________---------------------------__________________
    ________________     hex2bin, bin2hex      __________________
    ----------------___________________________------------------
  */

  static u_char hex2bin(u_char c)
  {
    return (isdigit(c) ? (c)-'0': ((toupper(c))-'A')+10)  & 0xf;
  }

  static u_char bin2hex(int nib)
  {
    return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib);
  }

  /*_________________---------------------------__________________
    _________________   printHex, hexToBinary   __________________
    -----------------___________________________------------------
  */

  int printHex(const u_char *a, int len, u_char *buf, int bufLen, int prefix)
  {
    int b = 0;
    if(prefix) {
      buf[b++] = '0';
      buf[b++] = 'x';
    }
    for(int i = 0; i < len; i++) {
      if(b > (bufLen - 2)) return 0; // must be room for 2 characters
      u_char byte = a[i];
      buf[b++] = bin2hex(byte >> 4);
      buf[b++] = bin2hex(byte & 0x0f);
    }

    // add NUL termination
    buf[b] = '\0';

    return b;
  }

  int hexToBinary(char *hex, u_char *bin, uint32_t binLen)
  {
    // read from hex into bin, up to max binLen chars, return number written
    char *h = hex;
    u_char *b = bin;
    u_char c;
    uint32_t i = 0;

    while((c = *h++) != '\0') {
      if(isxdigit(c)) {
	u_char val = hex2bin(c);
	if(isxdigit(*h)) {
	  c = *h++;
	  val = (val << 4) | hex2bin(c);
	}
	*b++ = val;
	if(++i >= binLen) return i;
      }
      else if(c != '.' &&
	      c != '-' &&
	      c != ':') { // allow a variety of byte-separators
	return i;
      }
    }
    return i;
  }

  /*_________________---------------------------__________________
    _________________       fcntl utils         __________________
    -----------------___________________________------------------
  */
  static void setNonBlocking(int fd) {
    // set the socket to non-blocking
    int fdFlags = fcntl(fd, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, fdFlags) < 0) {
      myLog("fcntl(O_NONBLOCK) failed: %s\n", strerror(errno));
    }
  }

  static void setCloseOnExec(int fd) {
    // make sure it doesn't get inherited, e.g. when we fork a script
    int fdFlags = fcntl(fd, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(fd, F_SETFD, fdFlags) < 0) {
      myLog("fcntl(F_SETFD=FD_CLOEXEC) failed: %s\n", strerror(errno));
    }
  }

  /*_________________---------------------------__________________
    _________________    UTNLGeneric_pid        __________________
    -----------------___________________________------------------
    choose a 32-bit id that is likely to be unique even if more
    than one module in this process wants to bind a netlink socket
  */

  uint32_t UTNLGeneric_pid(uint32_t mod_id) {
    return (mod_id << 16) | getpid();
  }

  /*_________________---------------------------__________________
    _________________    UTNLGeneric_open       __________________
    -----------------___________________________------------------
  */

  int UTNLGeneric_open(uint32_t mod_id) {
    int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if(nl_sock < 0) {
      myLog("nl_sock open failed: %s\n", strerror(errno));
      return -1;
    }

    // bind to a suitable id
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
			      .nl_pid = UTNLGeneric_pid(mod_id) };
    if(bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
      myLog("UTNLGeneric_open: bind failed: %s\n", strerror(errno));

    setNonBlocking(nl_sock);
    setCloseOnExec(nl_sock);
    return nl_sock;
  }

  /*_________________---------------------------__________________
    _________________      UTNLGeneric_send     __________________
    -----------------___________________________------------------
  */

  int UTNLGeneric_send(int sockfd, uint32_t mod_id, int type, int cmd, int req_type, void *req, int req_len, int req_footprint, uint32_t seqNo) {
    struct nlmsghdr nlh = { };
    struct genlmsghdr ge = { };
    struct nlattr attr = { };

    attr.nla_len = sizeof(attr) + req_len;
    attr.nla_type = req_type;

    ge.cmd = cmd;
    ge.version = 1;

    nlh.nlmsg_len = NLMSG_LENGTH(req_footprint + sizeof(attr) + sizeof(ge));
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_type = type;
    nlh.nlmsg_seq = seqNo;
    nlh.nlmsg_pid = UTNLGeneric_pid(mod_id);

    struct iovec iov[4] = {
      { .iov_base = &nlh,  .iov_len = sizeof(nlh) },
      { .iov_base = &ge,   .iov_len = sizeof(ge) },
      { .iov_base = &attr, .iov_len = sizeof(attr) },
      { .iov_base = req,   .iov_len = req_footprint }
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = iov, .msg_iovlen = 4 };
    return sendmsg(sockfd, &msg, 0);
  }


  /*_________________---------------------------__________________
    _________________    getFamily_PSAMPLE      __________________
    -----------------___________________________------------------
  */

  static void getFamily_PSAMPLE(PST *pst)
  {
    myLog("getFamily\n");
#define PST_FAM_LEN sizeof(PSAMPLE_GENL_NAME)
#define PST_FAM_FOOTPRINT NLMSG_ALIGN(PST_FAM_LEN)
    char fam_name[PST_FAM_FOOTPRINT] = {};
    memcpy(fam_name, PSAMPLE_GENL_NAME, PST_FAM_LEN);
    UTNLGeneric_send(pst->nl_sock,
		     pst->id,
		     GENL_ID_CTRL,
		     CTRL_CMD_GETFAMILY,
		     CTRL_ATTR_FAMILY_NAME,
		     fam_name, PST_FAM_LEN, PST_FAM_FOOTPRINT,
		     ++pst->nl_seq);
  }

  /*_________________---------------------------__________________
    _________________    joinGroup_PSAMPLE      __________________
    -----------------___________________________------------------
  */

  static void joinGroup_PSAMPLE(PST *pst)
  {
    myLog("joinGroup %u\n", pst->group_id);
    // register for the multicast group_id
    if(setsockopt(pst->nl_sock,
		  SOL_NETLINK,
		  NETLINK_ADD_MEMBERSHIP,
		  &pst->group_id,
		  sizeof(pst->group_id)) == -1) {
      myLog("error joining PSAMPLE netlink group %u : %s\n",
	    pst->group_id,
	    strerror(errno));
    }
  }

  /*_________________---------------------------__________________
    _________________  processNetlink_GENERIC   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_GENERIC(PST *pst, struct nlmsghdr *nlh)
  {
    char *msg = (char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    myLog("generic netlink CMD = %u\n", genl->cmd);

    for(int offset = GENL_HDRLEN; offset < msglen; ) {
      struct nlattr *attr = (struct nlattr *)(msg + offset);
      if(attr->nla_len == 0 ||
	 (attr->nla_len + offset) > msglen) {
	myLog("processNetlink_GENERIC attr parse error\n");
	break; // attr parse error
      }
      char *attr_datap = (char *)attr + NLA_HDRLEN;
      switch(attr->nla_type) {
      case CTRL_ATTR_VERSION:
	pst->genetlink_version = *(uint32_t *)attr_datap;
	break;
      case CTRL_ATTR_FAMILY_ID:
	pst->family_id = *(uint16_t *)attr_datap;
	myLog("generic family id: %u\n", pst->family_id); 
	break;
      case CTRL_ATTR_FAMILY_NAME:
	myLog("generic family name: %s\n", attr_datap); 
	break;
      case CTRL_ATTR_MCAST_GROUPS:
	for(int grp_offset = NLA_HDRLEN; grp_offset < attr->nla_len;) {
	  struct nlattr *grp_attr = (struct nlattr *)(msg + offset + grp_offset);
	  if(grp_attr->nla_len == 0 ||
	     (grp_attr->nla_len + grp_offset) > attr->nla_len) {
	    myLog("processNetlink_GENERIC grp_attr parse error\n");
	    break;
	  }
	  char *grp_name=NULL;
	  uint32_t grp_id=0;
	  for(int gf_offset = NLA_HDRLEN; gf_offset < grp_attr->nla_len; ) {
	    struct nlattr *gf_attr = (struct nlattr *)(msg + offset + grp_offset + gf_offset);
	    if(gf_attr->nla_len == 0 ||
	       (gf_attr->nla_len + gf_offset) > grp_attr->nla_len) {
	      myLog("processNetlink_GENERIC gf_attr parse error\n");
	      break;
	    }
	    char *grp_attr_datap = (char *)gf_attr + NLA_HDRLEN;
	    switch(gf_attr->nla_type) {
	    case CTRL_ATTR_MCAST_GRP_NAME:
	      grp_name = grp_attr_datap;
	      myLog("psample multicast group: %s\n", grp_name); 
	      break;
	    case CTRL_ATTR_MCAST_GRP_ID:
	      grp_id = *(uint32_t *)grp_attr_datap;
	      myLog("psample multicast group id: %u\n", grp_id); 
	      break;
	    }
	    gf_offset += NLMSG_ALIGN(gf_attr->nla_len);
	  }
	  if(pst->group_id == 0
	     && grp_name
	     && grp_id
	     && !strcmp(grp_name, PSAMPLE_NL_MCGRP_SAMPLE_NAME)) {
	    myLog("psample found group %s=%u\n", grp_name, grp_id);
	    pst->group_id = grp_id;
	    joinGroup_PSAMPLE(pst);
	  }

	  grp_offset += NLMSG_ALIGN(grp_attr->nla_len);
	}
	break;
      default:
	myLog("psample attr type: %u (nested=%u) len: %u\n",
	      attr->nla_type,
	      attr->nla_type & NLA_F_NESTED,
	      attr->nla_len);
      }
      offset += NLMSG_ALIGN(attr->nla_len);
    }
  }


  /*_________________---------------------------__________________
    _________________  processNetlink_PSAMPLE   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_PSAMPLE(PST *pst, struct nlmsghdr *nlh)
  {
    u_char *msg = (u_char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    myLog("psample netlink (type=%u) CMD = %u\n", nlh->nlmsg_type, genl->cmd);

    uint16_t ifin=0,ifout=0;
    u_char *pkt=NULL;
    uint32_t pkt_len=0;
    uint32_t hdr_len=0;
    uint32_t grp_no=0;
    uint32_t grp_seq=0;
    uint32_t sample_n=0;
    uint16_t e_queue=0;
    uint64_t e_depth=0;
    uint64_t e_delay=0;

    // TODO: tunnel encap/decap may be avaiable too

    for(int offset = GENL_HDRLEN; offset < msglen; ) {
      struct nlattr *ps_attr = (struct nlattr *)(msg + offset);
      if(ps_attr->nla_len == 0 ||
	 (ps_attr->nla_len + offset) > msglen) {
	myLog("processNetlink_PSAMPLE attr parse error");
	break;
      }
      u_char *datap = msg + offset + NLA_HDRLEN;
      switch(ps_attr->nla_type) {
      case PSAMPLE_ATTR_IIFINDEX: ifin = *(uint16_t *)datap; break;
      case PSAMPLE_ATTR_OIFINDEX: ifout = *(uint16_t *)datap; break;
      case PSAMPLE_ATTR_ORIGSIZE: pkt_len = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_SAMPLE_GROUP: grp_no = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_GROUP_SEQ: grp_seq = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_SAMPLE_RATE: sample_n = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_DATA: pkt = datap; hdr_len = ps_attr->nla_len; break;
      case PST_PSAMPLE_ATTR_OUT_TC: e_queue = *(uint16_t *)datap; break;
      case PST_PSAMPLE_ATTR_OUT_TC_OCC: e_depth = *(uint64_t *)datap; break;
      case PST_PSAMPLE_ATTR_LATENCY: e_delay = *(uint64_t *)datap; break;
      }
      offset += NLMSG_ALIGN(ps_attr->nla_len);
    }

    myLog("grp=%u in=%u out=%u n=%u seq=%u pktlen=%u hdrlen=%u pkt=%p q=%u depth=%"PRIu64" delay=%"PRIu64"\n",
	  grp_no,
	  ifin,
	  ifout,
	  sample_n,
	  grp_seq,
	  pkt_len,
	  hdr_len,
	  pkt,
	  e_queue,
	  e_depth,
	  e_delay);
  }

  /*_________________---------------------------__________________
    _________________    processNetlink         __________________
    -----------------___________________________------------------
  */

  static void processNetlink(PST *pst, struct nlmsghdr *nlh)
  {
    if(nlh->nlmsg_type == NETLINK_GENERIC) {
      processNetlink_GENERIC(pst, nlh);
    }
    else if(nlh->nlmsg_type == pst->family_id) {
      processNetlink_PSAMPLE(pst, nlh);
    }
  }

  /*_________________---------------------------__________________
    _________________   readNetlink_PSAMPLE     __________________
    -----------------___________________________------------------
  */

  static void readNetlink_PSAMPLE(PST *pst, int fd)
  {
    uint8_t recv_buf[PST_PSAMPLE_READNL_RCV_BUF];
    int batch = 0;
    for( ; batch < PST_PSAMPLE_READNL_BATCH; batch++) {
      int numbytes = recv(fd, recv_buf, sizeof(recv_buf), 0);
      if(numbytes <= 0)
	break;
      struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
      while(NLMSG_OK(nlh, numbytes)){
	if(nlh->nlmsg_type == NLMSG_DONE)
	  break;
	if(nlh->nlmsg_type == NLMSG_ERROR){
	  struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(nlh);
	  if(err_msg->error == 0) {
	    myLog("received Netlink ACK\n");
	  }
	  else {
	    // TODO: parse NLMSGERR_ATTR_OFFS to get offset?  Might be helpful
	    myLog("error in netlink message: %d : %s\n",
		  err_msg->error,
		  strerror(-err_msg->error));
	  }
	  break;
	}
	processNetlink(pst, nlh);
	nlh = NLMSG_NEXT(nlh, numbytes);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    socket reading         __________________
    -----------------___________________________------------------
  */

  typedef void (*PSTReadCB)(PST *pst, int sock);

  static void socketRead(PST *pst, uint32_t select_mS, PSTReadCB readCB) {
    fd_set readfds;
    FD_ZERO(&readfds);
    sigset_t emptyset;
    sigemptyset(&emptyset);
    FD_SET(pst->nl_sock, &readfds);
    int max_fd = pst->nl_sock;
    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = select_mS * 1000000;
    int nfds = pselect(max_fd + 1,
		       &readfds,
		       (fd_set *)NULL,
		       (fd_set *)NULL,
		       &timeout,
		       &emptyset);
    // see if we got anything
    if(nfds > 0) {
      if(FD_ISSET(pst->nl_sock, &readfds))
	(*readCB)(pst, pst->nl_sock);
    }
    else if(nfds < 0) {
      // may return prematurely if a signal was caught, in which case nfds will be
      // -1 and errno will be set to EINTR.  If we get any other error, abort.
      if(errno != EINTR) {
	myLog("pselect() returned %d : %s\n", nfds, strerror(errno));
	abort();
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    PSSpec new             __________________
    -----------------___________________________------------------
  */

  static PSSpec *PSSpec_new(PST *pst) {
    return calloc(1, sizeof(PSSpec));
  }

  /*_________________---------------------------__________________
    _________________    PSSpec free            __________________
    -----------------___________________________------------------
  */

  static void PSSpec_free(PST *pst, PSSpec *spec) {
    for(uint32_t ii = 0; ii < __PST_PSAMPLE_ATTR_MAX; ii++) {
      PSAttr *psa = &spec->attr[ii];
      if(psa->onheap)
	free(psa->val.iov_base);
    }
    free(spec);
  }

  /*_________________---------------------------__________________
    _________________    PSSpec setAttr         __________________
    -----------------___________________________------------------
  */

  static void setAttrValue(PSSpec *spec, EnumPSTAttributes type, void *val, int len) {
    PSAttr *psa = &spec->attr[type];
    assert(psa->included == NO); // make sure we don't set the same field twice
    psa->included = YES;
    psa->attr.nla_type = type;
    psa->attr.nla_len = sizeof(psa->attr) + len;
    int len_w_pad = NLMSG_ALIGN(len);
    psa->val.iov_len = len_w_pad;
    if(len_w_pad <= 8) {
      psa->buf64 = 0;
      psa->val.iov_base = &psa->buf64;
    }
    else {
      psa->val.iov_base = calloc(1, len_w_pad);
      psa->onheap = YES;
    }
    memcpy(psa->val.iov_base, val, len);
    spec->n_attrs++;
    spec->attrs_len += sizeof(psa->attr);
    spec->attrs_len += len_w_pad;
  }

  // break this switch up by type to help enforce expectations. Separate fns for
  // u16, u32, u64 and binary buffer.

  static bool PSSpec_setAttr16(PST *pst, PSSpec *spec, EnumPSTAttributes type, uint16_t val16) {
    switch(type) {
    case PST_PSAMPLE_ATTR_OUT_TC:
    case PST_PSAMPLE_ATTR_PROTO:
      setAttrValue(spec, type, &val16, sizeof(val16));
      break;
    default:
      myLog("ERROR: type=%d does not take 16-bit integer");
      abort();
    }
    return YES;
  }

  static bool PSSpec_setAttr32(PST *pst, PSSpec *spec, EnumPSTAttributes type, uint32_t val32) {
    switch(type) {
    case PST_PSAMPLE_ATTR_IIFINDEX:
    case PST_PSAMPLE_ATTR_OIFINDEX:
    case PST_PSAMPLE_ATTR_ORIGSIZE:
    case PST_PSAMPLE_ATTR_SAMPLE_GROUP:
    case PST_PSAMPLE_ATTR_GROUP_SEQ:
    case PST_PSAMPLE_ATTR_SAMPLE_RATE:
      setAttrValue(spec, type, &val32, sizeof(val32));
      break;
    default:
      myLog("ERROR: type=%d does not take 32-bit integer");
      abort();
    }
    return YES;
  }

  static bool PSSpec_setAttr64(PST *pst, PSSpec *spec, EnumPSTAttributes type, uint64_t val64) {
    switch(type) {
    case PST_PSAMPLE_ATTR_OUT_TC_OCC:
    case PST_PSAMPLE_ATTR_LATENCY:
    case PST_PSAMPLE_ATTR_TIMESTAMP:
      setAttrValue(spec, type, &val64, sizeof(val64));
      break;
    default:
      myLog("ERROR: type=%d does not take 64-bit integer");
      abort();
    }
    return YES;
  }

  static bool PSSpec_setAttr(PST *pst, PSSpec *spec, EnumPSTAttributes type, void *buf, int len) {
    switch(type) {
    case PST_PSAMPLE_ATTR_DATA:
      setAttrValue(spec, type, buf, len);
      break;
    case PST_PSAMPLE_ATTR_TUNNEL:
    case PST_PSAMPLE_ATTR_GROUP_REFCOUNT:
    case PST_PSAMPLE_ATTR_PAD:
      // TODO: implement - but might need to move to other setAttr* fn
      myLog("ERROR: type=%d not implemented");
      abort();
      break;
    default:
      myLog("ERROR: type=%d does not take binary buffer");
      abort();
    }
    return YES;
  }

  /*_________________---------------------------__________________
    _________________    PSSpect sethdr         __________________
    -----------------___________________________------------------
  */

  static void PSSpec_sethdr(PST *pst, PSSpec *spec) {
    spec->nlh.nlmsg_len = NLMSG_LENGTH(sizeof(spec->ge) + spec->attrs_len);
    spec->nlh.nlmsg_flags = 0;
    spec->nlh.nlmsg_type = pst->family_id;
    spec->nlh.nlmsg_seq = ++pst->nl_seq;
    spec->nlh.nlmsg_pid = UTNLGeneric_pid(pst->id);

    spec->ge.cmd = PSAMPLE_CMD_SAMPLE;
    spec->ge.version = PSAMPLE_GENL_VERSION;
  }

  /*_________________---------------------------__________________
    _________________    PSSpec_send            __________________
    -----------------___________________________------------------
  */

  static void PSSpec_send(PST *pst, PSSpec *spec) {
    myLog("send_psample getuid=%d geteuid=%d\n", getuid(), geteuid());

#define MAX_IOV_FRAGMENTS (2 * __PST_PSAMPLE_ATTR_MAX) + 2

    struct iovec iov[MAX_IOV_FRAGMENTS];
    uint32_t frag = 0;
    iov[frag].iov_base = &spec->nlh;
    iov[frag].iov_len = sizeof(spec->nlh);
    frag++;
    iov[frag].iov_base = &spec->ge;
    iov[frag].iov_len = sizeof(spec->ge);
    frag++;
    int nn = 0;
    for(uint32_t ii = 0; ii < __PST_PSAMPLE_ATTR_MAX; ii++) {
      PSAttr *psa = &spec->attr[ii];
      if(psa->included) {
	nn++;
	iov[frag].iov_base = &psa->attr;
	iov[frag].iov_len = sizeof(psa->attr);
	frag++;
	iov[frag] = psa->val; // struct copy
	frag++;
      }
    }
    assert(nn == spec->n_attrs);

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
			      .nl_groups = (1 << (pst->group_id-1)) };

    struct msghdr msg = { .msg_name = &sa,
			  .msg_namelen = sizeof(sa),
			  .msg_iov = iov,
			  .msg_iovlen = frag };

    int status = sendmsg(pst->nl_sock, &msg, 0);
    myLog("sendmsg returned %d\n", status);
    if(status <= 0)
      myLog("strerror(errno) = %s\n", strerror(errno));
  }

#ifdef PST_SHORT_CIRCUIT_TEST

  /*_________________---------------------------__________________
    _________________    PSSpec serialze        __________________
    -----------------___________________________------------------
  */

  static void my_append(char *msg, int *msglen, void *from, int len, int max_msglen) {
    assert(((*msglen) + len) <= max_msglen);
    memcpy((msg + *msglen), from, len);
    *msglen += len;
  }

  static struct nlmsghdr *PSSpec_serialize(PST *pst, PSSpec *spec) {
    // simulate the gather step in sendmsg (so we can short-circuit
    // and test the message before sending it on the netlink channel)
    int tot_len = sizeof(spec->nlh) + sizeof(spec->ge) + spec->attrs_len;
    char *msg = calloc(1, tot_len);
    int msglen = 0;
    my_append(msg, &msglen, &spec->nlh, sizeof(spec->nlh), tot_len);
    my_append(msg, &msglen, &spec->ge, sizeof(spec->ge), tot_len);
    
    int nn = 0;
    for(uint32_t ii = 0; ii < __PST_PSAMPLE_ATTR_MAX; ii++) {
      PSAttr *psa = &spec->attr[ii];
      if(psa->included) {
	nn++;
	my_append(msg, &msglen, &psa->attr, sizeof(psa->attr), tot_len);
	my_append(msg, &msglen, psa->val.iov_base, psa->val.iov_len, tot_len);
      }
    }
    // cross-checks
    assert(nn == spec->n_attrs);
    assert(msglen == tot_len);
    return (struct nlmsghdr *)msg;
  }

#endif

  /*_________________---------------------------__________________
    _________________           main            __________________
    -----------------___________________________------------------
  */

  int main(int argc, char **argv) {
    PST *pst = calloc(1, sizeof(PST));
    if(getuid() != 0) {
      fprintf(stderr, "must be ROOT to run this program\n");
      exit(-1);
    }

    // make sure psample kernel module is loaded
    int modprobe_status = system("modprobe psample");
    myLog("modprobe psample returned %d\n", modprobe_status);

    // open generic netlinke socket
    pst->id = 0;
    pst->nl_sock = UTNLGeneric_open(pst->id);
    if(pst->nl_sock < 0) {
      myLog("myNLGeneric_open failed : %s\n", strerror(errno));
      exit(-1);
    }
    myLog("netlink socket number = %u\n", UTNLGeneric_pid(pst->id));

    // family lookup
    getFamily_PSAMPLE(pst);
    // wait some number of mS for answer
    socketRead(pst, 500, readNetlink_PSAMPLE);
    if(pst->family_id == 0) {
      myLog("failed to get PSAMPLE family id\n");
      exit(-1);
    }

    // join multicast group. Is this strictly necessary
    // if we only want to send?
    joinGroup_PSAMPLE(pst);
    
    // NOTE: mod_psample in host-sflow expects egress samples (if present)
    // to be on a PSAMPLE_ATTR_SAMPLE_GROUP number that is 1 + the ingress
    // group number. (These group number attrbutes are  not to be confused
    // with the multicast group number we are sending to).

    PSSpec *sample = PSSpec_new(pst);
    PSSpec_setAttr32(pst, sample, PST_PSAMPLE_ATTR_SAMPLE_GROUP, 1);
    PSSpec_setAttr32(pst, sample, PST_PSAMPLE_ATTR_IIFINDEX, 7);
    PSSpec_setAttr32(pst, sample, PST_PSAMPLE_ATTR_OIFINDEX, 9);
    PSSpec_setAttr32(pst, sample, PST_PSAMPLE_ATTR_ORIGSIZE, 1514);
    PSSpec_setAttr32(pst, sample, PST_PSAMPLE_ATTR_GROUP_SEQ, 1);
    PSSpec_setAttr32(pst, sample, PST_PSAMPLE_ATTR_SAMPLE_RATE, 1000);

#define PST_MAX_HDR_LEN 512
    u_char buf[PST_MAX_HDR_LEN];
    char *hexhdr =  "080009010203080009040506080045000000000000000000000000";
    int len = hexToBinary(hexhdr, buf, PST_MAX_HDR_LEN);
    PSSpec_setAttr(pst, sample, PST_PSAMPLE_ATTR_DATA, buf, len);
    // PST_PSAMPLE_ATTR_TUNNEL
    // PST_PSAMPLE_ATTR_GROUP_REFCOUNT,
    // PST_PSAMPLE_ATTR_PAD,
    PSSpec_setAttr16(pst, sample, PST_PSAMPLE_ATTR_OUT_TC, 3);
    PSSpec_setAttr64(pst, sample, PST_PSAMPLE_ATTR_OUT_TC_OCC, 33333333);
    PSSpec_setAttr64(pst, sample, PST_PSAMPLE_ATTR_LATENCY, 123456);
    // PST_PSAMPLE_ATTR_TIMESTAMP,/* u64, nanoseconds */
    // ATTR_PROTO==1 => SFLHEADER_ETHERNET_ISO8023
    PSSpec_setAttr16(pst, sample, PST_PSAMPLE_ATTR_PROTO, 1);

    myLog("set headers...\n");
    PSSpec_sethdr(pst, sample);

#ifdef PST_SHORT_CIRCUIT_TEST
    myLog("serialize...\n");
    struct nlmsghdr *msg = PSSpec_serialize(pst, sample);
    myLog("print before sending...\n");
    processNetlink_PSAMPLE(pst, msg);
#endif

    myLog("send...\n");
    PSSpec_send(pst, sample);
    myLog("free...\n");
    PSSpec_free(pst, sample);

#ifdef PST_LISTEN_MODE
    myLog("start read loop...\n");
    // read loop
    for(;;) {
      socketRead(pst, 500, readNetlink_PSAMPLE);
    }
#endif
    return 0;
  }
