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
#include <linux/ethtool.h>
#include <linux/ethtool_netlink.h>
#include <net/if.h>
#include <signal.h>
#include <ctype.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#define ETT_ETHTOOL_READNL_RCV_BUF 8192
#define ETT_ETHTOOL_READNL_BATCH 100
#define ETT_ETHTOOL_RCVBUF 8000000
#define ETT_ETHTOOL_HEADER_SIZE 128
#define ETT_ETHTOOL_QUEUE 100
  
#define ETT_SHORT_CIRCUIT_TEST 1
#define ETT_LISTEN_MODE 1
  
  typedef uint32_t bool;
#define YES ((bool)1)
#define NO ((bool)0)

#ifndef ETHTOOL_GENL_NAME
  #define ETHTOOL_GENL_NAME "ethtool"
#endif

  // there doesn't seem to be an overrall max attr number, so just make space
  // for the one we are going to exercise here.
#define ETT_ETHTOOL_ATTR_MAX ETHTOOL_A_MODULE_EEPROM_MAX
  
  typedef struct _ETT {
    uint32_t id;
    int nl_sock;
    uint32_t nl_seq;
    uint32_t genetlink_version;
    uint16_t family_id;
    uint32_t group_id; // "monitor" group - what is this for?
  } ETT;

  typedef struct _ETAttr {
    bool included:1;
    bool onheap:1;
    struct nlattr attr;
    struct iovec val;
    uint64_t buf64;
  } ETAttr;
    
  typedef struct _ETSpec {
    struct nlmsghdr nlh;
    struct genlmsghdr ge;
    // there doesn't seem to be an overrall max attr number, so just make space
    // for the one we are going to exercise here.
    ETAttr attr[ETT_ETHTOOL_ATTR_MAX + 1];
    int n_attrs;
    int attrs_len;
  } ETSpec;


  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

#define LOGPREFIX "ettest: "

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
    _________________    Netlink macros         __________________
    -----------------___________________________------------------
  */

#define UTNLA_OK(nla,len)	((len) > 0 && (nla)->nla_len >= sizeof(struct nlattr) \
	&& (nla)->nla_len <= (len))
#define UTNLA_NEXT(nla,attrlen)	((attrlen) -= NLA_ALIGN((nla)->nla_len), \
	(struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#define UTNLA_LENGTH(len)	(NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define UTNLA_SPACE(len)	NLA_ALIGN(UTNLA_LENGTH(len))
#define UTNLA_DATA(nla)   ((void *)(((char *)(nla)) + UTNLA_LENGTH(0)))
#define UTNLA_PAYLOAD(nla) ((int)((nla)->nla_len) - UTNLA_LENGTH(0))

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

  int UTNLGeneric_send(int sockfd, uint32_t mod_id, int type, int cmd, int req_type, void *req, int req_len, uint32_t seqNo) {
    struct nlmsghdr nlh = { };
    struct genlmsghdr ge = { };
    struct nlattr attr = { };
    int req_footprint = NLMSG_ALIGN(req_len);

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
    _________________    getFamily_ETHTOOL      __________________
    -----------------___________________________------------------
  */

  static void getFamily_ETHTOOL(ETT *ett)
  {
    myLog("getFamily\n");
    UTNLGeneric_send(ett->nl_sock,
		     ett->id,
		     GENL_ID_CTRL,
		     CTRL_CMD_GETFAMILY,
		     CTRL_ATTR_FAMILY_NAME,
		     ETHTOOL_GENL_NAME,
		     sizeof(ETHTOOL_GENL_NAME)+1,
		     ++ett->nl_seq);
  }

  /*_________________---------------------------__________________
    _________________    joinGroup_ETHTOOL      __________________
    -----------------___________________________------------------
  */

  static void joinGroup_ETHTOOL(ETT *ett)
  {
    myLog("joinGroup %u\n", ett->group_id);
    // register for the multicast group_id
    if(setsockopt(ett->nl_sock,
		  SOL_NETLINK,
		  NETLINK_ADD_MEMBERSHIP,
		  &ett->group_id,
		  sizeof(ett->group_id)) == -1) {
      myLog("error joining ETHTOOL netlink group %u : %s\n",
	    ett->group_id,
	    strerror(errno));
    }
  }

  /*_________________---------------------------__________________
    _________________    query_ETHTOOL          __________________
    -----------------___________________________------------------
  */

  static void query_ETHTOOL(ETT *ett)
  {
#if 0
    UTNLGeneric_send(ett->nl_sock,
		     ett->id,
		     ett->family_id,
		     NET_DM_CMD_CONFIG,
		     NET_DM_ATTR_TRUNC_LEN,
		     &truncLen,
		     sizeof(truncLen),
		     ++ett->nl_seq);
#endif
  }

  /*_________________---------------------------__________________
    _________________  processNetlink_GENERIC   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_GENERIC(ETT *ett, struct nlmsghdr *nlh)
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
	ett->genetlink_version = *(uint32_t *)attr_datap;
	break;
      case CTRL_ATTR_FAMILY_ID:
	ett->family_id = *(uint16_t *)attr_datap;
	myLog("generic family id: %u\n", ett->family_id); 
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
	      myLog("ethtool multicast group: %s\n", grp_name); 
	      break;
	    case CTRL_ATTR_MCAST_GRP_ID:
	      grp_id = *(uint32_t *)grp_attr_datap;
	      myLog("ethtool multicast group id: %u\n", grp_id); 
	      break;
	    }
	    gf_offset += NLMSG_ALIGN(gf_attr->nla_len);
	  }
	  if(ett->group_id == 0
	     && grp_name
	     /* && grp_id == NET_DM_GRP_ALERT */) {
	    myLog("found group %s=%u\n", grp_name, grp_id);
	    ett->group_id = grp_id;
	    // joinGroup_ETHTOOL(ett);
	  }

	  grp_offset += NLMSG_ALIGN(grp_attr->nla_len);
	}
	break;
      default:
	myLog("attr type: %u (nested=%u) len: %u\n",
	      attr->nla_type,
	      attr->nla_type & NLA_F_NESTED,
	      attr->nla_len);
      }
      offset += NLMSG_ALIGN(attr->nla_len);
    }
  }


  /*_________________---------------------------__________________
    _________________  processNetlink_ETHTOOL   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_ETHTOOL(ETT *ett, struct nlmsghdr *nlh)
  {
    u_char *msg = (u_char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    myLog("ethtool netlink (type=%u) CMD = %u\n", nlh->nlmsg_type, genl->cmd);
    
    struct nlattr *attr = (struct nlattr *)(msg + GENL_HDRLEN);
    int len = msglen - GENL_HDRLEN;
    while(UTNLA_OK(attr, len)) {
      u_char *datap = UTNLA_DATA(attr);
      int datalen = UTNLA_PAYLOAD(attr);
      
      {
	u_char hex[1024];
	printHex(datap, datalen, hex, 1023, YES);
	myLog("nla_type=%u, datalen=%u, payload=%s\n", attr->nla_type, datalen, hex);
      }

      bool nested = attr->nla_type & NLA_F_NESTED;
      int attributeType = attr->nla_type & ~NLA_F_NESTED;
      switch(attributeType) {
      case ETHTOOL_A_STATS_HEADER:
	myLog("ETHTOOL_A_STATS_HEADER nested=%u, len=%u\n", nested, datalen);
	if(nested) {
	  struct nlattr *nst_attr = (struct nlattr *)datap;
	  int nst_len = datalen;
	  while(UTNLA_OK(nst_attr, nst_len)) {
	    switch(nst_attr->nla_type) {
	    case ETHTOOL_A_HEADER_DEV_NAME:
	      myLog("ETHTOOL_A_HEADER_DEV_NAME=%s\n", UTNLA_DATA(nst_attr));
	      break;
	    case ETHTOOL_A_HEADER_FLAGS:
	      myLog("ETHTOOL_A_HEADER_FLAGS=%0x%02x\n", *(uint32_t *)UTNLA_DATA(nst_attr));
	      break;
	    default:
	      myLog("nst_attr=%u\n", nst_attr->nla_type);
	      break;
	    }
	    nst_attr = UTNLA_NEXT(nst_attr, nst_len);
	  }
	}
      }
      attr = UTNLA_NEXT(attr, len);
    }
  }

  /*_________________---------------------------__________________
    _________________    processNetlink         __________________
    -----------------___________________________------------------
  */

  static void processNetlink(ETT *ett, struct nlmsghdr *nlh)
  {
    if(nlh->nlmsg_type == NETLINK_GENERIC) {
      processNetlink_GENERIC(ett, nlh);
    }
    else if(nlh->nlmsg_type == ett->family_id) {
      processNetlink_ETHTOOL(ett, nlh);
    }
  }

  /*_________________---------------------------__________________
    _________________   readNetlink_ETHTOOL     __________________
    -----------------___________________________------------------
  */

  static void readNetlink_ETHTOOL(ETT *ett, int fd)
  {
    uint8_t recv_buf[ETT_ETHTOOL_READNL_RCV_BUF];
    int batch = 0;
    for( ; batch < ETT_ETHTOOL_READNL_BATCH; batch++) {
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
	processNetlink(ett, nlh);
	nlh = NLMSG_NEXT(nlh, numbytes);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    socket reading         __________________
    -----------------___________________________------------------
  */

  typedef void (*ETTReadCB)(ETT *ett, int sock);

  static void socketRead(ETT *ett, uint32_t select_mS, ETTReadCB readCB) {
    fd_set readfds;
    FD_ZERO(&readfds);
    sigset_t emptyset;
    sigemptyset(&emptyset);
    FD_SET(ett->nl_sock, &readfds);
    int max_fd = ett->nl_sock;
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
      if(FD_ISSET(ett->nl_sock, &readfds))
	(*readCB)(ett, ett->nl_sock);
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
    _________________    ETSpec new             __________________
    -----------------___________________________------------------
  */

  static ETSpec *ETSpec_new(ETT *ett) {
    return calloc(1, sizeof(ETSpec));
  }

  /*_________________---------------------------__________________
    _________________    ETSpec free            __________________
    -----------------___________________________------------------
  */

  static void ETSpec_free(ETT *ett, ETSpec *spec) {
    for(uint32_t ii = 0; ii < ETT_ETHTOOL_ATTR_MAX; ii++) {
      ETAttr *eta = &spec->attr[ii];
      if(eta->onheap)
	free(eta->val.iov_base);
    }
    free(spec);
  }

  /*_________________---------------------------__________________
    _________________    ETSpec setAttr         __________________
    -----------------___________________________------------------
  */

  static void setAttrValue(ETSpec *spec, int type, void *val, int len) {
    ETAttr *eta = &spec->attr[type];
    assert(eta->included == NO); // make sure we don't set the same field twice
    eta->included = YES;
    eta->attr.nla_type = type;
    eta->attr.nla_len = sizeof(eta->attr) + len;
    int len_w_pad = NLMSG_ALIGN(len);
    eta->val.iov_len = len_w_pad;
    if(len_w_pad <= 8) {
      eta->buf64 = 0;
      eta->val.iov_base = &eta->buf64;
    }
    else {
      eta->val.iov_base = calloc(1, len_w_pad);
      eta->onheap = YES;
    }
    memcpy(eta->val.iov_base, val, len);
    spec->n_attrs++;
    spec->attrs_len += sizeof(eta->attr);
    spec->attrs_len += len_w_pad;
  }

  // break this switch up by type to help enforce expectations. Separate fns for
  // u16, u32, u64 and binary buffer.

  static bool ETSpec_setAttr16(ETT *ett, ETSpec *spec, int type, uint16_t val16) {
    setAttrValue(spec, type, &val16, sizeof(val16));
    return YES;
  }

  static bool ETSpec_setAttr32(ETT *ett, ETSpec *spec, int type, uint32_t val32) {
    setAttrValue(spec, type, &val32, sizeof(val32));
    return YES;
  }

  static bool ETSpec_setAttr64(ETT *ett, ETSpec *spec, int type, uint64_t val64) {
    setAttrValue(spec, type, &val64, sizeof(val64));
    return YES;
  }
  
  static bool ETSpec_setAttr(ETT *ett, ETSpec *spec, int type, void *buf, int len) {
    setAttrValue(spec, type, buf, len);
    return YES;
  }

  static void ETSpec_setAttrNested(ETSpec *spec, int type) {
    ETAttr *eta = &spec->attr[type];
    assert(eta->included == YES);
    eta->attr.nla_type |= NLA_F_NESTED;
  }
  
  /*_________________---------------------------__________________
    _________________    ETSpect sethdr         __________________
    -----------------___________________________------------------
  */

  static void ETSpec_sethdr(ETT *ett, ETSpec *spec) {
    spec->nlh.nlmsg_len = NLMSG_LENGTH(sizeof(spec->ge) + spec->attrs_len);
    spec->nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    spec->nlh.nlmsg_type = ett->family_id;
    spec->nlh.nlmsg_seq = ++ett->nl_seq;
    spec->nlh.nlmsg_pid = UTNLGeneric_pid(ett->id);

    spec->ge.cmd = ETHTOOL_MSG_STATS_GET; // ETHTOOL_MSG_MODULE_EEPROM_GET;
    spec->ge.version = ETHTOOL_GENL_VERSION;
  }

  /*_________________---------------------------__________________
    _________________    ETSpec_send            __________________
    -----------------___________________________------------------
  */

  static void ETSpec_send(ETT *ett, ETSpec *spec) {
    myLog("ETTSpec_send getuid=%d geteuid=%d\n", getuid(), geteuid());

#define MAX_IOV_FRAGMENTS (2 * ETT_ETHTOOL_ATTR_MAX) + 2

    struct iovec iov[MAX_IOV_FRAGMENTS];
    uint32_t frag = 0;
    iov[frag].iov_base = &spec->nlh;
    iov[frag].iov_len = sizeof(spec->nlh);
    frag++;
    iov[frag].iov_base = &spec->ge;
    iov[frag].iov_len = sizeof(spec->ge);
    frag++;
    int nn = 0;
    for(uint32_t ii = 0; ii < ETT_ETHTOOL_ATTR_MAX; ii++) {
      ETAttr *eta = &spec->attr[ii];
      if(eta->included) {
	nn++;
	iov[frag].iov_base = &eta->attr;
	iov[frag].iov_len = sizeof(eta->attr);
	frag++;
	iov[frag] = eta->val; // struct copy
	frag++;
      }
    }
    assert(nn == spec->n_attrs);

    struct sockaddr_nl sa = {
      .nl_family = AF_NETLINK,
      .nl_groups = 0 /* unicast */ /* (1 << (ett->group_id-1))*/
    };

    struct msghdr msg = { .msg_name = &sa,
			  .msg_namelen = sizeof(sa),
			  .msg_iov = iov,
			  .msg_iovlen = frag };

    int status = sendmsg(ett->nl_sock, &msg, 0);
    myLog("sendmsg returned %d\n", status);
    if(status <= 0)
      myLog("strerror(errno) = %s\n", strerror(errno));
  }


  /*_________________---------------------------__________________
    _________________    ETSpec serialze        __________________
    -----------------___________________________------------------
  */

  static void my_append(char *msg, int *msglen, void *from, int len, int max_msglen) {
    assert(((*msglen) + len) <= max_msglen);
    memcpy((msg + *msglen), from, len);
    *msglen += len;
  }

  static struct nlmsghdr *ETSpec_serialize(ETT *ett, ETSpec *spec) {
    // simulate the gather step in sendmsg (so we can short-circuit
    // and test the message before sending it on the netlink channel)
    int tot_len = sizeof(spec->nlh) + sizeof(spec->ge) + spec->attrs_len;
    char *msg = calloc(1, tot_len);
    int msglen = 0;
    my_append(msg, &msglen, &spec->nlh, sizeof(spec->nlh), tot_len);
    my_append(msg, &msglen, &spec->ge, sizeof(spec->ge), tot_len);
    
    int nn = 0;
    for(uint32_t ii = 0; ii < ETT_ETHTOOL_ATTR_MAX; ii++) {
      ETAttr *eta = &spec->attr[ii];
      if(eta->included) {
	nn++;
	my_append(msg, &msglen, &eta->attr, sizeof(eta->attr), tot_len);
	my_append(msg, &msglen, eta->val.iov_base, eta->val.iov_len, tot_len);
      }
    }
    // cross-checks
    assert(nn == spec->n_attrs);
    assert(msglen == tot_len);
    return (struct nlmsghdr *)msg;
  }

  /*_________________---------------------------__________________
    _________________           main            __________________
    -----------------___________________________------------------
  */

  int main(int argc, char **argv) {
    char *dev = NULL;
    ETT *ett = calloc(1, sizeof(ETT));
    if(getuid() != 0) {
      fprintf(stderr, "must be ROOT to run this program\n");
      exit(-1);
    }
    if(argc != 2
       || argv[1] == NULL) {
      fprintf(stderr, "usage: %s <deviceName>\n", argv[0]);
      exit(-2);
    }
    dev = argv[1];
    // open generic netlinke socket
    ett->id = 0;
    ett->nl_sock = UTNLGeneric_open(ett->id);
    if(ett->nl_sock < 0) {
      myLog("myNLGeneric_open failed : %s\n", strerror(errno));
      exit(-1);
    }
    myLog("netlink socket number = %u\n", UTNLGeneric_pid(ett->id));

    // family lookup
    getFamily_ETHTOOL(ett);
    // wait some number of mS for answer
    socketRead(ett, 500, readNetlink_ETHTOOL);
    if(ett->family_id == 0) {
      myLog("failed to get ETHTOOL family id\n");
      exit(-1);
    }

    // join multicast group. Is this strictly necessary
    // if we only want to send?
    // joinGroup_ETHTOOL(ett);

    // ========== make a request ================
    ETSpec *request = ETSpec_new(ett);
 
    // make nested attrs for header
    ETSpec *nested = ETSpec_new(ett);
    ETSpec_setAttr(ett, nested, ETHTOOL_A_HEADER_DEV_NAME, dev, strlen(dev));
    ETSpec_setAttr32(ett, nested, ETHTOOL_A_HEADER_FLAGS, ETHTOOL_FLAG_STATS);
    // do we set other nested attrs here too? (EEPROM_OFFSET, EEPROM_LENGTH etc.)
    // flatten so we can add as header
    struct nlmsghdr *nmsg = ETSpec_serialize(ett, nested);
    char *nmsg_attrs = (char *)nmsg + sizeof(nested->nlh) + sizeof(nested->ge);
    // and add to request
    ETSpec_setAttr(ett, request, ETHTOOL_A_STATS_HEADER, nmsg_attrs, nested->attrs_len);
    ETSpec_setAttrNested(request, ETHTOOL_A_STATS_HEADER);
    ETSpec_sethdr(ett, request);

#ifdef ETT_SHORT_CIRCUIT_TEST
    myLog("serialize...\n");
    struct nlmsghdr *msg = ETSpec_serialize(ett, request);
    myLog("print before sending...\n");
    processNetlink_ETHTOOL(ett, msg);
#endif

    myLog("send...\n");
    ETSpec_send(ett, request);
    myLog("free...\n");
    ETSpec_free(ett, request);

    // TODO: read from file
    // TODO: sent bursts of drops
    
#ifdef ETT_LISTEN_MODE
    myLog("start read loop...\n");
    // read loop
    for(;;) {
      socketRead(ett, 500, readNetlink_ETHTOOL);
    }
#endif
    return 0;
  }
