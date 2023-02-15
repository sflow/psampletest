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
#include <linux/net_dropmon.h>
#include <net/if.h>
#include <signal.h>
#include <ctype.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#define DMT_DROPMON_READNL_RCV_BUF 8192
#define DMT_DROPMON_READNL_BATCH 100
#define DMT_DROPMON_RCVBUF 8000000
#define DMT_DROPMON_HEADER_SIZE 128
#define DMT_DROPMON_QUEUE 100
  
#define DMT_SHORT_CIRCUIT_TEST 1
#define DMT_LISTEN_MODE 1
  
  typedef uint32_t bool;
#define YES ((bool)1)
#define NO ((bool)0)

#ifndef NET_DM_GENL_NAME
  #define NET_DM_GENL_NAME "NET_DM"
#endif
  
  // Shadow the attributes in linux/net_dropmon.h so
  // we can easily compile/test fields that are not
  // defined on the kernel we are compiling on.
#define NET_DM_ATTR_UNSPEC 0
#define NET_DM_ATTR_ALERT_MODE 1
#define NET_DM_ATTR_PC 2
#define NET_DM_ATTR_SYMBOL 3
#define NET_DM_ATTR_IN_PORT 4
#define NET_DM_ATTR_TIMESTAMP 5
#define NET_DM_ATTR_PROTO 6
#define NET_DM_ATTR_PAYLOAD 7
#define NET_DM_ATTR_PAD 8
#define NET_DM_ATTR_TRUNC_LEN 9
#define NET_DM_ATTR_ORIG_LEN 10
#define NET_DM_ATTR_QUEUE_LEN 11
#define NET_DM_ATTR_STATS 12
#define NET_DM_ATTR_HW_STATS 13
#define NET_DM_ATTR_ORIGIN 14
#define NET_DM_ATTR_HW_TRAP_GROUP_NAME 15
#define NET_DM_ATTR_HW_TRAP_NAME 16
#define NET_DM_ATTR_HW_ENTRIES 17
#define NET_DM_ATTR_HW_ENTRY 18
#define NET_DM_ATTR_HW_TRAP_COUNT 19
#define NET_DM_ATTR_SW_DROPS 20
#define NET_DM_ATTR_HW_DROPS 21
#define NET_DM_ATTR_FLOW_ACTION_COOKIE 22
#define NET_DM_ATTR_MAX 22
  
  typedef struct _DMT {
    uint32_t id;
    int nl_sock;
    uint32_t nl_seq;
    uint32_t genetlink_version;
    uint16_t family_id;
    uint32_t group_id;
  } DMT;

  typedef struct _DMAttr {
    bool included:1;
    bool onheap:1;
    struct nlattr attr;
    struct iovec val;
    uint64_t buf64;
  } DMAttr;
    
  typedef struct _DMSpec {
    struct nlmsghdr nlh;
    struct genlmsghdr ge;
    DMAttr attr[NET_DM_ATTR_MAX];
    int n_attrs;
    int attrs_len;
  } DMSpec;


  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

#define LOGPREFIX "dmtest: "

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
    _________________    getFamily_DROPMON      __________________
    -----------------___________________________------------------
  */

  static void getFamily_DROPMON(DMT *dmt)
  {
    myLog("getFamily\n");
    UTNLGeneric_send(dmt->nl_sock,
		     dmt->id,
		     GENL_ID_CTRL,
		     CTRL_CMD_GETFAMILY,
		     CTRL_ATTR_FAMILY_NAME,
		     NET_DM_GENL_NAME,
		     sizeof(NET_DM_GENL_NAME)+1,
		     ++dmt->nl_seq);
  }

  /*_________________---------------------------__________________
    _________________    joinGroup_DROPMON      __________________
    -----------------___________________________------------------
  */

  static void joinGroup_DROPMON(DMT *dmt)
  {
    myLog("joinGroup %u\n", dmt->group_id);
    // register for the multicast group_id
    if(setsockopt(dmt->nl_sock,
		  SOL_NETLINK,
		  NETLINK_ADD_MEMBERSHIP,
		  &dmt->group_id,
		  sizeof(dmt->group_id)) == -1) {
      myLog("error joining DROPMON netlink group %u : %s\n",
	    dmt->group_id,
	    strerror(errno));
    }
  }

  /*_________________---------------------------__________________
    _________________    start_DROPMON          __________________
    -----------------___________________________------------------
*/

  static int start_DROPMON(DMT *dmt, bool startIt)
  {
    struct nlmsghdr nlh = { };
    struct genlmsghdr ge = { };
    struct nlattr attr1 = { };
    struct nlattr attr2 = { };

    attr1.nla_len = sizeof(attr1);
    attr1.nla_type = NET_DM_ATTR_SW_DROPS;
    attr2.nla_len = sizeof(attr2);
    attr2.nla_type = NET_DM_ATTR_HW_DROPS;

    ge.cmd = startIt
      ? NET_DM_CMD_START
      : NET_DM_CMD_STOP;
    ge.version = 1;

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ge) + sizeof(attr1) + sizeof(attr2));
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_type = dmt->family_id;
    nlh.nlmsg_seq = ++dmt->nl_seq;
    nlh.nlmsg_pid = UTNLGeneric_pid(dmt->id);

    struct iovec iov[4] = {
      { .iov_base = &nlh,  .iov_len = sizeof(nlh) },
      { .iov_base = &ge,   .iov_len = sizeof(ge) },
      { .iov_base = &attr1, .iov_len = sizeof(attr1) },
      { .iov_base = &attr2, .iov_len = sizeof(attr2) },
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = iov, .msg_iovlen = 4 };
    return sendmsg(dmt->nl_sock, &msg, 0);
  }

  /*_________________---------------------------__________________
    _________________    configure_DROPMON      __________________
    -----------------___________________________------------------
  */

  static void configure_DROPMON(DMT *dmt)
  {
    uint8_t alertMode = NET_DM_ALERT_MODE_PACKET;
    uint32_t truncLen = DMT_DROPMON_HEADER_SIZE;
    uint32_t queueLen = DMT_DROPMON_QUEUE;
    // This control will fail if the feed has already been configured and started externally.
    // TODO: set these in one message?
    UTNLGeneric_send(dmt->nl_sock,
		     dmt->id,
		     dmt->family_id,
		     NET_DM_CMD_CONFIG,
		     NET_DM_ATTR_TRUNC_LEN,
		     &truncLen,
		     sizeof(truncLen),
		     ++dmt->nl_seq);
    UTNLGeneric_send(dmt->nl_sock,
		     dmt->id,
		     dmt->family_id,
		     NET_DM_CMD_CONFIG,
		     NET_DM_ATTR_QUEUE_LEN,
		     &queueLen,
		     sizeof(queueLen),
		     ++dmt->nl_seq);
    UTNLGeneric_send(dmt->nl_sock,
		     dmt->id,
		     dmt->family_id,
		     NET_DM_CMD_CONFIG,
		     NET_DM_ATTR_ALERT_MODE,
		     &alertMode,
		     sizeof(alertMode),
		     ++dmt->nl_seq);
  }

  /*_________________---------------------------__________________
    _________________  processNetlink_GENERIC   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_GENERIC(DMT *dmt, struct nlmsghdr *nlh)
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
	dmt->genetlink_version = *(uint32_t *)attr_datap;
	break;
      case CTRL_ATTR_FAMILY_ID:
	dmt->family_id = *(uint16_t *)attr_datap;
	myLog("generic family id: %u\n", dmt->family_id); 
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
	      myLog("dropmon multicast group: %s\n", grp_name); 
	      break;
	    case CTRL_ATTR_MCAST_GRP_ID:
	      grp_id = *(uint32_t *)grp_attr_datap;
	      myLog("dropmon multicast group id: %u\n", grp_id); 
	      break;
	    }
	    gf_offset += NLMSG_ALIGN(gf_attr->nla_len);
	  }
	  if(dmt->group_id == 0
	     && grp_name
	     && grp_id == NET_DM_GRP_ALERT) {
	    myLog("dropmon found group %s=%u\n", grp_name, grp_id);
	    dmt->group_id = grp_id;
	    joinGroup_DROPMON(dmt);
	  }

	  grp_offset += NLMSG_ALIGN(grp_attr->nla_len);
	}
	break;
      default:
	myLog("dropmon attr type: %u (nested=%u) len: %u\n",
	      attr->nla_type,
	      attr->nla_type & NLA_F_NESTED,
	      attr->nla_len);
      }
      offset += NLMSG_ALIGN(attr->nla_len);
    }
  }


  /*_________________---------------------------__________________
    _________________  processNetlink_DROPMON   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_DROPMON(DMT *dmt, struct nlmsghdr *nlh)
  {
    u_char *msg = (u_char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    myLog("dropmon netlink (type=%u) CMD = %u\n", nlh->nlmsg_type, genl->cmd);
    // some parameters to pick up for cross-check below
    uint32_t trunc_len=0;
    uint32_t orig_len=0;
    char *hw_group=NULL;
    char *hw_name=NULL;
    char *sw_symbol=NULL;
    
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
      case NET_DM_ATTR_ALERT_MODE:
	myLog( "dropmon: u8=ALERT_MODE=%u\n", *(uint8_t *)datap);
	// enum net_dm_alert_mode NET_DM_ALERT_MODE_PACKET == 1
	// TODO: what to do if not packet?
	break;
      case NET_DM_ATTR_PC:
	myLog("dropmon: u64=PC=0x%"PRIx64"\n", *(uint64_t *)datap);
	break;
      case NET_DM_ATTR_SYMBOL:
	myLog("dropmon: string=ATTR_SYMBOL=%s\n", datap);
	sw_symbol = (char *)datap;
	break;
      case NET_DM_ATTR_IN_PORT:
	myLog("dropmon: nested=IN_PORT\n");
	if(!nested) {
	  myLog("dropmon: forcing NET_DM_ATTR_IN_PORT to be interpreted as nested attribute\n");
	  nested = YES;
	}
	if(nested) {
	  struct nlattr *port_attr = (struct nlattr *)datap;
	  int port_len = datalen;
	  while(UTNLA_OK(port_attr, port_len)) {
	    switch(port_attr->nla_type) {
	    case NET_DM_ATTR_PORT_NETDEV_IFINDEX:
	      myLog("dropmon: u32=NETDEV_IFINDEX=%u\n", *(uint32_t *)UTNLA_DATA(port_attr));
	      //discard.input = *(uint32_t *)UTNLA_DATA(port_attr);
	      break;
	    case NET_DM_ATTR_PORT_NETDEV_NAME:
	      myLog("dropmon: string=NETDEV_NAME=%s\n", (char *)UTNLA_DATA(port_attr));
	      break;
	    }
	    port_attr = UTNLA_NEXT(port_attr, port_len);
	  }
	}
	break;
      case NET_DM_ATTR_TIMESTAMP:
	myLog("dropmon: u64=TIMESTAMP=%"PRIu64"\n", *(uint64_t *)datap);
	break;
      case NET_DM_ATTR_PROTO:
	myLog("dropmon: u16=PROTO=0x%04x\n", *(uint16_t *)datap);
	// TODO: do we need to interpret protocol = 0x0800 as IPv4 and 0x86DD as IPv6?
	// We seem to get MAC layer here, but will that always be the case?
	break;
      case NET_DM_ATTR_PAYLOAD:
	myLog("dropmon: PAYLOAD\n");
	//	hdrElem.flowType.header.header_length = datalen;
	//	hdrElem.flowType.header.header_bytes = datap;
	//	hdrElem.flowType.header.stripped = 4;
	break;
      case NET_DM_ATTR_PAD:
	myLog("dropmon: PAD\n");
	break;
      case NET_DM_ATTR_TRUNC_LEN:
	myLog("dropmon: u32=TRUNC_LEN=%u\n", *(uint32_t *)datap);
	trunc_len = *(uint32_t *)datap;
	break;
      case NET_DM_ATTR_ORIG_LEN:
	myLog("dropmon: u32=ORIG_LEN=%u\n", *(uint32_t *)datap);
	orig_len = *(uint32_t *)datap;
	break;
      case NET_DM_ATTR_QUEUE_LEN:
	myLog("dropmon: u32=QUEUE_LEN=%u\n", *(uint32_t *)datap);
	break;
      case NET_DM_ATTR_STATS:
	myLog("dropmon: nested=ATTR_STATS\n");
	break;
      case NET_DM_ATTR_HW_STATS:
	myLog("dropmon: nested=HW_STATS\n");
	break;
      case NET_DM_ATTR_ORIGIN:
	myLog("dropmon: u16=ORIGIN=%u\n", *(uint16_t *)datap);
	break;
      case NET_DM_ATTR_HW_TRAP_GROUP_NAME:
	myLog("dropmon: string=TRAP_GROUP_NAME=%s\n", datap);
	hw_group = (char *)datap;
	break;
      case NET_DM_ATTR_HW_TRAP_NAME:
	myLog("dropmon: string=TRAP_NAME=%s\n", datap);
	hw_name = (char *)datap;
	break;
      case NET_DM_ATTR_HW_ENTRIES:
	myLog("dropmon: nested=HW_ENTRIES\n");
	break;
      case NET_DM_ATTR_HW_ENTRY:
	myLog("dropmon: nested=HW_ENTRY\n");
	break;
      case NET_DM_ATTR_HW_TRAP_COUNT:
	myLog("dropmon: u32=SW_DROPS=%u\n", *(uint32_t *)datap);
	break;
      case NET_DM_ATTR_SW_DROPS:
	myLog("dropmon: flag=SW_DROPS\n");
	break;
      case NET_DM_ATTR_HW_DROPS:
	myLog("dropmon: flag=HW_DROPS\n");
	break;
      }
      attr = UTNLA_NEXT(attr, len);
    }
  }

  /*_________________---------------------------__________________
    _________________    processNetlink         __________________
    -----------------___________________________------------------
  */

  static void processNetlink(DMT *dmt, struct nlmsghdr *nlh)
  {
    if(nlh->nlmsg_type == NETLINK_GENERIC) {
      processNetlink_GENERIC(dmt, nlh);
    }
    else if(nlh->nlmsg_type == dmt->family_id) {
      processNetlink_DROPMON(dmt, nlh);
    }
  }

  /*_________________---------------------------__________________
    _________________   readNetlink_DROPMON     __________________
    -----------------___________________________------------------
  */

  static void readNetlink_DROPMON(DMT *dmt, int fd)
  {
    uint8_t recv_buf[DMT_DROPMON_READNL_RCV_BUF];
    int batch = 0;
    for( ; batch < DMT_DROPMON_READNL_BATCH; batch++) {
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
	processNetlink(dmt, nlh);
	nlh = NLMSG_NEXT(nlh, numbytes);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    socket reading         __________________
    -----------------___________________________------------------
  */

  typedef void (*DMTReadCB)(DMT *dmt, int sock);

  static void socketRead(DMT *dmt, uint32_t select_mS, DMTReadCB readCB) {
    fd_set readfds;
    FD_ZERO(&readfds);
    sigset_t emptyset;
    sigemptyset(&emptyset);
    FD_SET(dmt->nl_sock, &readfds);
    int max_fd = dmt->nl_sock;
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
      if(FD_ISSET(dmt->nl_sock, &readfds))
	(*readCB)(dmt, dmt->nl_sock);
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
    _________________    DMSpec new             __________________
    -----------------___________________________------------------
  */

  static DMSpec *DMSpec_new(DMT *dmt) {
    return calloc(1, sizeof(DMSpec));
  }

  /*_________________---------------------------__________________
    _________________    DMSpec free            __________________
    -----------------___________________________------------------
  */

  static void DMSpec_free(DMT *dmt, DMSpec *spec) {
    for(uint32_t ii = 0; ii < NET_DM_ATTR_MAX; ii++) {
      DMAttr *dma = &spec->attr[ii];
      if(dma->onheap)
	free(dma->val.iov_base);
    }
    free(spec);
  }

  /*_________________---------------------------__________________
    _________________    DMSpec setAttr         __________________
    -----------------___________________________------------------
  */

  static void setAttrValue(DMSpec *spec, int type, void *val, int len) {
    DMAttr *dma = &spec->attr[type];
    assert(dma->included == NO); // make sure we don't set the same field twice
    dma->included = YES;
    dma->attr.nla_type = type;
    dma->attr.nla_len = sizeof(dma->attr) + len;
    int len_w_pad = NLMSG_ALIGN(len);
    dma->val.iov_len = len_w_pad;
    if(len_w_pad <= 8) {
      dma->buf64 = 0;
      dma->val.iov_base = &dma->buf64;
    }
    else {
      dma->val.iov_base = calloc(1, len_w_pad);
      dma->onheap = YES;
    }
    memcpy(dma->val.iov_base, val, len);
    spec->n_attrs++;
    spec->attrs_len += sizeof(dma->attr);
    spec->attrs_len += len_w_pad;
  }

  // break this switch up by type to help enforce expectations. Separate fns for
  // u16, u32, u64 and binary buffer.

  static bool DMSpec_setAttr16(DMT *dmt, DMSpec *spec, int type, uint16_t val16) {
    setAttrValue(spec, type, &val16, sizeof(val16));
    return YES;
  }

  static bool DMSpec_setAttr32(DMT *dmt, DMSpec *spec, int type, uint32_t val32) {
    setAttrValue(spec, type, &val32, sizeof(val32));
    return YES;
  }

  static bool DMSpec_setAttr64(DMT *dmt, DMSpec *spec, int type, uint64_t val64) {
    setAttrValue(spec, type, &val64, sizeof(val64));
    return YES;
  }
  
  static bool DMSpec_setAttr(DMT *dmt, DMSpec *spec, int type, void *buf, int len) {
    setAttrValue(spec, type, buf, len);
    return YES;
  }

  /*_________________---------------------------__________________
    _________________    DMSpect sethdr         __________________
    -----------------___________________________------------------
  */

  static void DMSpec_sethdr(DMT *dmt, DMSpec *spec) {
    spec->nlh.nlmsg_len = NLMSG_LENGTH(sizeof(spec->ge) + spec->attrs_len);
    spec->nlh.nlmsg_flags = 0;
    spec->nlh.nlmsg_type = dmt->family_id;
    spec->nlh.nlmsg_seq = ++dmt->nl_seq;
    spec->nlh.nlmsg_pid = UTNLGeneric_pid(dmt->id);

    spec->ge.cmd = NET_DM_CMD_PACKET_ALERT;
    spec->ge.version = 0;
  }

  /*_________________---------------------------__________________
    _________________    DMSpec_send            __________________
    -----------------___________________________------------------
  */

  static void DMSpec_send(DMT *dmt, DMSpec *spec) {
    myLog("send_dropmon getuid=%d geteuid=%d\n", getuid(), geteuid());

#define MAX_IOV_FRAGMENTS (2 * NET_DM_ATTR_MAX) + 2

    struct iovec iov[MAX_IOV_FRAGMENTS];
    uint32_t frag = 0;
    iov[frag].iov_base = &spec->nlh;
    iov[frag].iov_len = sizeof(spec->nlh);
    frag++;
    iov[frag].iov_base = &spec->ge;
    iov[frag].iov_len = sizeof(spec->ge);
    frag++;
    int nn = 0;
    for(uint32_t ii = 0; ii < NET_DM_ATTR_MAX; ii++) {
      DMAttr *dma = &spec->attr[ii];
      if(dma->included) {
	nn++;
	iov[frag].iov_base = &dma->attr;
	iov[frag].iov_len = sizeof(dma->attr);
	frag++;
	iov[frag] = dma->val; // struct copy
	frag++;
      }
    }
    assert(nn == spec->n_attrs);

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
			      .nl_groups = (1 << (dmt->group_id-1)) };

    struct msghdr msg = { .msg_name = &sa,
			  .msg_namelen = sizeof(sa),
			  .msg_iov = iov,
			  .msg_iovlen = frag };

    int status = sendmsg(dmt->nl_sock, &msg, 0);
    myLog("sendmsg returned %d\n", status);
    if(status <= 0)
      myLog("strerror(errno) = %s\n", strerror(errno));
  }

#ifdef DMT_SHORT_CIRCUIT_TEST

  /*_________________---------------------------__________________
    _________________    DMSpec serialze        __________________
    -----------------___________________________------------------
  */

  static void my_append(char *msg, int *msglen, void *from, int len, int max_msglen) {
    assert(((*msglen) + len) <= max_msglen);
    memcpy((msg + *msglen), from, len);
    *msglen += len;
  }

  static struct nlmsghdr *DMSpec_serialize(DMT *dmt, DMSpec *spec) {
    // simulate the gather step in sendmsg (so we can short-circuit
    // and test the message before sending it on the netlink channel)
    int tot_len = sizeof(spec->nlh) + sizeof(spec->ge) + spec->attrs_len;
    char *msg = calloc(1, tot_len);
    int msglen = 0;
    my_append(msg, &msglen, &spec->nlh, sizeof(spec->nlh), tot_len);
    my_append(msg, &msglen, &spec->ge, sizeof(spec->ge), tot_len);
    
    int nn = 0;
    for(uint32_t ii = 0; ii < NET_DM_ATTR_MAX; ii++) {
      DMAttr *dma = &spec->attr[ii];
      if(dma->included) {
	nn++;
	my_append(msg, &msglen, &dma->attr, sizeof(dma->attr), tot_len);
	my_append(msg, &msglen, dma->val.iov_base, dma->val.iov_len, tot_len);
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
    DMT *dmt = calloc(1, sizeof(DMT));
    if(getuid() != 0) {
      fprintf(stderr, "must be ROOT to run this program\n");
      exit(-1);
    }

    // make sure dropmon kernel module is loaded
    int modprobe_status = system("modprobe dropmon");
    myLog("modprobe dropmon returned %d\n", modprobe_status);

    // open generic netlinke socket
    dmt->id = 0;
    dmt->nl_sock = UTNLGeneric_open(dmt->id);
    if(dmt->nl_sock < 0) {
      myLog("myNLGeneric_open failed : %s\n", strerror(errno));
      exit(-1);
    }
    myLog("netlink socket number = %u\n", UTNLGeneric_pid(dmt->id));

    // family lookup
    getFamily_DROPMON(dmt);
    // wait some number of mS for answer
    socketRead(dmt, 500, readNetlink_DROPMON);
    if(dmt->family_id == 0) {
      myLog("failed to get DROPMON family id\n");
      exit(-1);
    }

    // join multicast group. Is this strictly necessary
    // if we only want to send?
    joinGroup_DROPMON(dmt);

    // compile fake packet header
#define DMT_MAX_HDR_LEN 512
    u_char buf[DMT_MAX_HDR_LEN];
    char *hexhdr =  "080009010203080009040506080045000000000000000000000000";
    int len = hexToBinary(hexhdr, buf, DMT_MAX_HDR_LEN);
    
    // ========== simulate Software drop ================
    DMSpec *sw_sample = DMSpec_new(dmt);
    DMSpec_setAttr16(dmt, sw_sample, NET_DM_ATTR_ORIGIN, 0);
    DMSpec_setAttr64(dmt, sw_sample, NET_DM_ATTR_PC, 0xffffffff00112233);
    DMSpec_setAttr(dmt, sw_sample, NET_DM_ATTR_PAYLOAD, buf, len);
    char *sym = "dropmontest_software";
    DMSpec_setAttr(dmt, sw_sample, NET_DM_ATTR_SYMBOL, sym, strlen(sym));
    DMSpec_setAttr32(dmt, sw_sample, NET_DM_ATTR_ORIG_LEN, 1400);
    DMSpec_setAttr16(dmt, sw_sample, NET_DM_ATTR_PROTO, 0x0800);
    myLog("set headers...\n");
    DMSpec_sethdr(dmt, sw_sample);
#ifdef DMT_SHORT_CIRCUIT_TEST
    myLog("serialize...\n");
    struct nlmsghdr *sw_msg = DMSpec_serialize(dmt, sw_sample);
    myLog("print before sending...\n");
    processNetlink_DROPMON(dmt, sw_msg);
#endif
    myLog("send...\n");
    DMSpec_send(dmt, sw_sample);
    myLog("free...\n");
    DMSpec_free(dmt, sw_sample);


    // ========== simulate Hardware drop ================
    DMSpec *hw_sample = DMSpec_new(dmt);
    DMSpec_setAttr16(dmt, hw_sample, NET_DM_ATTR_ORIGIN, 0);
    DMSpec_setAttr(dmt, hw_sample, NET_DM_ATTR_PAYLOAD, buf, len);
    char *grp = "dropmontest_hw_grp";
    char *evt = "dropmontest_hw_evt";
    DMSpec_setAttr(dmt, hw_sample, NET_DM_ATTR_HW_TRAP_GROUP_NAME, grp, strlen(grp));
    DMSpec_setAttr(dmt, hw_sample, NET_DM_ATTR_HW_TRAP_NAME, evt, strlen(evt));
    DMSpec_setAttr32(dmt, hw_sample, NET_DM_ATTR_ORIG_LEN, 1400);
    DMSpec_setAttr16(dmt, hw_sample, NET_DM_ATTR_PROTO, 0x0800);
    myLog("set headers...\n");
    DMSpec_sethdr(dmt, hw_sample);
#ifdef DMT_SHORT_CIRCUIT_TEST
    myLog("serialize...\n");
    struct nlmsghdr *hw_msg = DMSpec_serialize(dmt, hw_sample);
    myLog("print before sending...\n");
    processNetlink_DROPMON(dmt, hw_msg);
#endif
    myLog("send...\n");
    DMSpec_send(dmt, hw_sample);
    myLog("free...\n");
    DMSpec_free(dmt, hw_sample);

    // TODO: read from file
    // TODO: sent bursts of drops
    
#ifdef DMT_LISTEN_MODE
    myLog("start read loop...\n");
    // read loop
    for(;;) {
      socketRead(dmt, 500, readNetlink_DROPMON);
    }
#endif
    return 0;
  }
