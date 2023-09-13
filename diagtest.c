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
#include <signal.h>
#include <ctype.h>
#include <netdb.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define IND_READNL_RCV_BUF 8192
#define IND_READNL_BATCH 10
  
  typedef uint32_t bool;
#define YES ((bool)1)
#define NO ((bool)0)

  // pull in the struct tcp_info from a recent OS so we can
  // compile this on one platform and run successfully in another
  struct my_tcp_info {
    __u8	tcpi_state;
    __u8	tcpi_ca_state;
    __u8	tcpi_retransmits;
    __u8	tcpi_probes;
    __u8	tcpi_backoff;
    __u8	tcpi_options;
    __u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

    __u32	tcpi_rto;
    __u32	tcpi_ato;
    __u32	tcpi_snd_mss;
    __u32	tcpi_rcv_mss;

    __u32	tcpi_unacked;
    __u32	tcpi_sacked;
    __u32	tcpi_lost;
    __u32	tcpi_retrans;
    __u32	tcpi_fackets;

    /* Times. */
    __u32	tcpi_last_data_sent;
    __u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
    __u32	tcpi_last_data_recv;
    __u32	tcpi_last_ack_recv;

    /* Metrics. */
    __u32	tcpi_pmtu;
    __u32	tcpi_rcv_ssthresh;
    __u32	tcpi_rtt;
    __u32	tcpi_rttvar;
    __u32	tcpi_snd_ssthresh;
    __u32	tcpi_snd_cwnd;
    __u32	tcpi_advmss;
    __u32	tcpi_reordering;

    __u32	tcpi_rcv_rtt;
    __u32	tcpi_rcv_space;

    __u32	tcpi_total_retrans;

    __u64	tcpi_pacing_rate;
    __u64	tcpi_max_pacing_rate;
    __u64	tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
    __u64	tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
    __u32	tcpi_segs_out;	     /* RFC4898 tcpEStatsPerfSegsOut */
    __u32	tcpi_segs_in;	     /* RFC4898 tcpEStatsPerfSegsIn */

    __u32	tcpi_notsent_bytes;
    __u32	tcpi_min_rtt;
    __u32	tcpi_data_segs_in;	/* RFC4898 tcpEStatsDataSegsIn */
    __u32	tcpi_data_segs_out;	/* RFC4898 tcpEStatsDataSegsOut */

    __u64       tcpi_delivery_rate;

    __u64	tcpi_busy_time;      /* Time (usec) busy sending data */
    __u64	tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
    __u64	tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

    __u32	tcpi_delivered;
    __u32	tcpi_delivered_ce;

    __u64	tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
    __u64	tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
    __u32	tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
    __u32	tcpi_reord_seen;     /* reordering events seen */

    __u32	tcpi_rcv_ooopack;    /* Out-of-order packets received */

    __u32	tcpi_snd_wnd;	     /* peer's advertised receive window after
				      * scaling (bytes)
				      */
  };
  /* Replicate some definitions we need from inet_diag.h here,
     so we can compile on an older OS if necessary. This assumes
     that the kernel will only ever add to these, and never
     change them.
  */
#define INET_DIAG_INFO 2
#define INET_DIAG_SHUTDOWN 8
#define INET_DIAG_MARK 15
#define INET_DIAG_CLASS_ID 17
#define INET_DIAG_CGROUP_ID 21
#define INET_DIAG_SOCKOPT 22

  typedef struct {
    uint32_t addr;
  } SFLIPv4;
  
  typedef struct {
    u_char addr[16];
  } SFLIPv6;
  
  typedef union _SFLAddress_value {
    SFLIPv4 ip_v4;
    SFLIPv6 ip_v6;
  } SFLAddress_value;
  
  enum SFLAddress_type {
    SFLADDRESSTYPE_UNDEFINED = 0,
    SFLADDRESSTYPE_IP_V4 = 1,
    SFLADDRESSTYPE_IP_V6 = 2
  };
  
  typedef struct _SFLAddress {
    uint32_t type;           /* enum SFLAddress_type */
    SFLAddress_value address;
  } SFLAddress;
  
  typedef struct _IND {
    // params
    SFLAddress src;
    SFLAddress dst;
    uint16_t sport;
    uint16_t dport;
    uint32_t ifIndex;
    bool udp:1;
    bool dump:1;
    // diag
    int nl_sock;
    uint32_t nl_seq_tx;
    struct inet_diag_req_v2 conn_req;
    struct inet_diag_sockid normalized_id;
  } IND;

  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

#define LOGPREFIX "diagtest: "

  void myLogv(char *fmt, va_list args) {
    fprintf(stdout, LOGPREFIX);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
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

  /*________________---------------------------__________________
    ________________      SFLAddress utils     __________________
    ----------------___________________________------------------
  */

  char *SFLAddress_print(SFLAddress *addr, char *buf, size_t len) {
    return (char *)inet_ntop(addr->type == SFLADDRESSTYPE_IP_V6 ? AF_INET6 : AF_INET,
			     &addr->address,
			     buf,
			     len);
  }

  static bool parseOrResolveAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family, int numeric)
  {
    struct addrinfo *info = NULL;
    struct addrinfo hints = { 0 };
    hints.ai_socktype = SOCK_DGRAM; // constrain this so we don't get lots of answers
    hints.ai_family = family; // PF_INET, PF_INET6 or 0
    if(numeric) {
      hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    }
    int err = getaddrinfo(name, NULL, &hints, &info);
    if(err) {
      myLog("getaddrinfo() failed: %s", gai_strerror(err));
      switch(err) {
      case EAI_NONAME: break;
      case EAI_NODATA: break;
      case EAI_AGAIN: break; // loop and try again?
      default: myLog("getaddrinfo() error: %s", gai_strerror(err)); break;
      }
      return NO;
    }

    if(info == NULL) return NO;

    if(info->ai_addr) {
      // answer is now in info - a linked list of answers with sockaddr values.
      // extract the address we want from the first one. $$$ should perhaps
      // traverse the list and look for an IPv4 address since that is more
      // likely to work?
      switch(info->ai_family) {
      case PF_INET:
	{
	  struct sockaddr_in *ipsoc = (struct sockaddr_in *)info->ai_addr;
	  memset(addr, 0, sizeof(*addr)); // avoid artifacts in unused bytes
	  addr->type = SFLADDRESSTYPE_IP_V4;
	  addr->address.ip_v4.addr = ipsoc->sin_addr.s_addr;
	  if(sa)
	    memcpy(sa, info->ai_addr, info->ai_addrlen);
	}
	break;
      case PF_INET6:
	{
	  struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
	  memset(addr, 0, sizeof(*addr)); // avoid artifacts in unused bytes
	  addr->type = SFLADDRESSTYPE_IP_V6;
	  memcpy(&addr->address.ip_v6, &ip6soc->sin6_addr, 16);
	  if(sa)
	    memcpy(sa, info->ai_addr, info->ai_addrlen);
	}
	break;
      default:
	myLog("get addrinfo: unexpected address family: %d", info->ai_family);
	return NO;
	break;
      }
    }
    // free the dynamically allocated data before returning
    freeaddrinfo(info);
    return YES;
  }

  bool lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
  {
    return parseOrResolveAddress(name, sa, addr, family, NO);
  }

  bool parseNumericAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
  {
    return parseOrResolveAddress(name, sa, addr, family, YES);
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
      myLog("fcntl(O_NONBLOCK) failed: %s", strerror(errno));
    }
  }

  static void setCloseOnExec(int fd) {
    // make sure it doesn't get inherited, e.g. when we fork a script
    int fdFlags = fcntl(fd, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(fd, F_SETFD, fdFlags) < 0) {
      myLog("fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
    }
  }


  /*_________________---------------------------__________________
    _________________    UTNLDiag_open          __________________
    -----------------___________________________------------------
  */

  int UTNLDiag_open(void) {
    // open the netlink monitoring socket
    int nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if(nl_sock < 0) {
      myLog("nl_sock open failed: %s", strerror(errno));
      return -1;
    }
    setNonBlocking(nl_sock);
    setCloseOnExec(nl_sock);
    return nl_sock;
  }

  /*__________________---------------------------__________________
    __________________ UTNLDiag_sockid_normalize __________________
    ------------------___________________________------------------
  */

  bool UTNLDiag_sockid_normalize(struct inet_diag_sockid *sockid) {
    bool rewritten = NO;
    if(sockid->idiag_src[0] == 0
       && sockid->idiag_src[1] == 0
       && ntohl(sockid->idiag_src[2]) == 0xFFFF) {
      // convert v4-as-v6 to v4
      sockid->idiag_src[0] = sockid->idiag_src[3];
      sockid->idiag_src[2] = 0;
      sockid->idiag_src[3] = 0;
      rewritten = YES;
    }
    if(sockid->idiag_dst[0] == 0
       && sockid->idiag_dst[1] == 0
       && ntohl(sockid->idiag_dst[2]) == 0xFFFF) {
      // convert v4-as-v6 to v4
      sockid->idiag_dst[0] = sockid->idiag_dst[3];
      sockid->idiag_dst[2] = 0;
      sockid->idiag_dst[3] = 0;
      rewritten = YES;
    }
    if(sockid->idiag_if) {
      sockid->idiag_if = 0;
      rewritten = YES;
    }
    if(sockid->idiag_cookie[0] != INET_DIAG_NOCOOKIE
       || sockid->idiag_cookie[1] != INET_DIAG_NOCOOKIE) {
      sockid->idiag_cookie[0] = INET_DIAG_NOCOOKIE;
      sockid->idiag_cookie[1] = INET_DIAG_NOCOOKIE;
      rewritten = YES;
    }
    return rewritten;
  }
  /*_________________---------------------------__________________
    _________________      UTNLDiag_send        __________________
    -----------------___________________________------------------
  */

  int UTNLDiag_send(int sockfd, void *req, int req_len, bool dump, uint32_t seqNo) {
    struct nlmsghdr nlh = { };
    nlh.nlmsg_len = NLMSG_LENGTH(req_len);
    nlh.nlmsg_flags = NLM_F_REQUEST;
    if(dump)
      nlh.nlmsg_flags |= NLM_F_DUMP;
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh.nlmsg_seq = seqNo;

    struct iovec iov[2] = {
      { .iov_base = &nlh, .iov_len = sizeof(nlh) },
      { .iov_base = req,  .iov_len = req_len }
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = iov, .msg_iovlen = 2 };
    return sendmsg(sockfd, &msg, 0);
  }

  /*_________________---------------------------__________________
    _________________     UTNLDiag_recv         __________________
    -----------------___________________________------------------
  */
  typedef void (*UTNLDiagCB)(void *magic, int sockFd, uint32_t seqNo, struct inet_diag_msg *diag_msg, int rtalen);

  void UTNLDiag_recv(void *magic, int sockFd, UTNLDiagCB diagCB)
  {
    uint8_t recv_buf[IND_READNL_RCV_BUF];
    int batch = 0;
    if(sockFd > 0) {
      for( ; batch < IND_READNL_BATCH; batch++) {
	int numbytes = recv(sockFd, recv_buf, sizeof(recv_buf), 0);
	if(numbytes <= 0)
	  break;
	struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
	while(NLMSG_OK(nlh, numbytes)){
	  if(nlh->nlmsg_type == NLMSG_DONE)
	    break;
	  if(nlh->nlmsg_type == NLMSG_ERROR){
            struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(nlh);
	    // Frequently see:
	    // "device or resource busy" (especially with NLM_F_DUMP set)
	    // "netlink error" (IPv6 but connection not established)
	    // so only log when debugging:
	    myLog("Error in netlink message: %d : %s", err_msg->error, strerror(-err_msg->error));
	    break;
	  }
	  if(nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY) {
	    struct inet_diag_msg *diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
	    int rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
	    (*diagCB)(magic, sockFd, nlh->nlmsg_seq, diag_msg, rtalen);
	  }
	  nlh = NLMSG_NEXT(nlh, numbytes);
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    UTNLDiag_sockid_print  __________________
    -----------------___________________________------------------
  */

  char *UTNLDiag_sockid_print(struct inet_diag_sockid *sockid) {
    static char buf[256];
    snprintf(buf, 256, "%08x:%08x:%08x:%08x %u - %08x:%08x:%08x:%08x %u if:%u cookie: %0x8:%08x",
	     ntohl(sockid->idiag_src[0]),
	     ntohl(sockid->idiag_src[1]),
	     ntohl(sockid->idiag_src[2]),
	     ntohl(sockid->idiag_src[3]),
	     ntohs(sockid->idiag_sport),
	     ntohl(sockid->idiag_dst[0]),
	     ntohl(sockid->idiag_dst[1]),
	     ntohl(sockid->idiag_dst[2]),
	     ntohl(sockid->idiag_dst[3]),
	     ntohs(sockid->idiag_dport),
	     ntohl(sockid->idiag_if),
	     ntohl(sockid->idiag_cookie[0]),
	     ntohl(sockid->idiag_cookie[1]));
    return buf;
  }
  
  /*_________________---------------------------__________________
    _________________     parse_diag_msg        __________________
    -----------------___________________________------------------
  */

  static void parse_diag_msg(IND* ind, struct inet_diag_msg *diag_msg, int rtalen, uint32_t seqNo)
  {
    if(diag_msg == NULL)
      return;
    if(diag_msg->idiag_family != AF_INET
       && diag_msg->idiag_family != AF_INET6)
      return;

    // user info.  Prefer getpwuid_r() if avaiable...
    struct passwd *uid_info = getpwuid(diag_msg->idiag_uid);
    myLog("diag_msg: UID=%u(%s) inode=%u",
	  diag_msg->idiag_uid,
	  uid_info ? uid_info->pw_name : "<user not found>",
	  diag_msg->idiag_inode);
    if(rtalen > 0) {
      uint64_t cgroup_id = 0;
      uint32_t mark = 0;
      uint8_t shutdown = 0;
      uint32_t class_id = 0;
      uint16_t sockopt_flags = 0;
      
      struct rtattr *attr = (struct rtattr *)(diag_msg + 1);
      
      while(RTA_OK(attr, rtalen)) {
	switch (attr->rta_type) {
	case INET_DIAG_MARK: {
	  if(RTA_PAYLOAD(attr) == 4) {
	    memcpy(&mark, RTA_DATA(attr), 4);
	    myLog("INET_DIAG_MARK=%u", mark);
	  }
	}
	  break;
	case INET_DIAG_CGROUP_ID: {
	  if(RTA_PAYLOAD(attr) == 8) {
	    memcpy(&cgroup_id, RTA_DATA(attr), 8);
	    myLog("INET_DIAG_CGROUP_ID=%"PRIu64, cgroup_id);
	  }
	}
	  break;
	case INET_DIAG_SHUTDOWN: {
	  if(RTA_PAYLOAD(attr) == 1) {
	    memcpy(&shutdown, RTA_DATA(attr), 1);
	    myLog("INET_DIAG_SHUTDOWN=%u", shutdown);
	  }
	}
	  break;
	case INET_DIAG_CLASS_ID: {
	  if(RTA_PAYLOAD(attr) == 4) {
	    memcpy(&class_id, RTA_DATA(attr), 4);
	    myLog("INET_DIAG_CLASS=%u", class_id);
	  }
	}
	  break;
	case INET_DIAG_SOCKOPT: {
	  if(RTA_PAYLOAD(attr) == 2) {
	    memcpy(&sockopt_flags, RTA_DATA(attr), 2);
	    myLog("INET_DIAG_SOCKOPT=0x%02X", sockopt_flags);
	  }
	}
	  break;
	case  INET_DIAG_INFO: {
	  // The payload is a struct tcp_info as defined in linux/tcp.h,  but we use
	  // struct my_tcp_info - copied from a system running kernel rev 4.7.3.  New
	  // fields are only added to the end of the struct so this works for forwards
	  // and backwards compatibilty:
	  // Unknown fields in in the sFlow structure should be exported as 0,  so we
	  // initialize our struct my_tcp_info with zeros.  Then we copy in the tcp_info
	  // we get from the kernel, up to the size of struct my_tcp_info.  Now if the
	  // kernel tcp_info has fewer fields the extras will all be 0 (correct),
	  // or if the kernel's has more fields they will simply be ignored (no problem,
	  // but we should check back in case they are worth exporting!)
	  struct my_tcp_info tcpi = { 0 };
	  int readLen = RTA_PAYLOAD(attr);
	  if(readLen > sizeof(struct my_tcp_info)) {
	    myLog("New kernel has new fields in struct tcp_info. Check it out!");
	    readLen = sizeof(struct my_tcp_info);
	  }
	  memcpy(&tcpi, RTA_DATA(attr), readLen);
	  myLog("TCP diag: RTT=%uuS (variance=%uuS) [%s]",
		tcpi.tcpi_rtt, tcpi.tcpi_rttvar,
		UTNLDiag_sockid_print(&diag_msg->id));
	}
	  break;
	default:
	  myLog("INET_DIAG_(%u): payload=%u", attr->rta_type, RTA_PAYLOAD(attr));
	  break;
	}
	attr = RTA_NEXT(attr, rtalen);
      }
    }
  }


  static void diagCB(void *magic, int sockFd, uint32_t seqNo, struct inet_diag_msg *diag_msg, int rtalen) {
      parse_diag_msg((IND *)magic, diag_msg, rtalen, seqNo);
  }
  
  static void readNetlink_DIAG(IND *ind, int sock) {
    UTNLDiag_recv((void *)ind, ind->nl_sock, diagCB);
  }
  

  /*_________________---------------------------__________________
    _________________    socket reading         __________________
    -----------------___________________________------------------
  */

  typedef void (*INDReadCB)(IND *ind, int sock);

  static void socketRead(IND *ind, uint32_t select_mS, INDReadCB readCB) {
    fd_set readfds;
    FD_ZERO(&readfds);
    sigset_t emptyset;
    sigemptyset(&emptyset);
    FD_SET(ind->nl_sock, &readfds);
    int max_fd = ind->nl_sock;
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
      if(FD_ISSET(ind->nl_sock, &readfds))
	(*readCB)(ind, ind->nl_sock);
    }
    else if(nfds < 0) {
      // may return prematurely if a signal was caught, in which case nfds will be
      // -1 and errno will be set to EINTR.  If we get any other error, abort.
      if(errno != EINTR) {
	myLog("pselect() returned %d : %s", nfds, strerror(errno));
	abort();
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       lookup_sample       __________________
    -----------------___________________________------------------
  */

  static void lookup_sample(IND *ind, SFLAddress *ipsrc, SFLAddress *ipdst, bool udp, uint16_t sport, uint16_t dport, uint32_t ifIndex) {
    // OK,  we are going to look this one up
    // just the established TCP connections
    ind->conn_req.sdiag_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
    if(udp) {
      // TODO: is this necessary?
      ind->conn_req.idiag_states = 0xFFFF;
      ind->conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    }
    else {
      ind->conn_req.idiag_states = (1<<TCP_ESTABLISHED);
      // just the tcp_info
       ind->conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    }
    
    myLog("idiag_states=0x%x, idiag_ext=0x%x",
	  ind->conn_req.idiag_states,
	  ind->conn_req.idiag_ext);
    
    // copy into inet_diag_sockid
    struct inet_diag_sockid *sockid = &ind->conn_req.id;
    // addresses
    if(ipsrc->type == SFLADDRESSTYPE_IP_V4) {
      ind->conn_req.sdiag_family = AF_INET;
      memcpy(sockid->idiag_src, &ipsrc->address.ip_v4, 4);
      memcpy(sockid->idiag_dst, &ipdst->address.ip_v4, 4);
    }
    else {
      ind->conn_req.sdiag_family = AF_INET6;
      memcpy(sockid->idiag_src, &ipsrc->address.ip_v6, 16);
      memcpy(sockid->idiag_dst, &ipdst->address.ip_v6, 16);
    }
    // L4 ports - network byte order
    sockid->idiag_sport = htons(sport);
    sockid->idiag_dport = htons(dport);
    // specify the ifIndex in case the socket is bound
    // see INET_MATCH in net/ipv4/inet_hashtables.c
    // (if not bound, then does not care, so OK to always fill in, right?)
    sockid->idiag_if = ifIndex;
    // I have no cookie :(
    sockid->idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    sockid->idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    UTNLDiag_send(ind->nl_sock,
		  &ind->conn_req,
		  sizeof(ind->conn_req),
		  (udp||ind->dump), // always set DUMP flag if UDP
		  ++ind->nl_seq_tx);
  }

  /*_________________---------------------------__________________
    _________________      parseSocket          __________________
    -----------------___________________________------------------
  */

  static bool parseSocket(char *str, SFLAddress *addr, uint16_t *p_port) {
    char *delim = "-";
    int family = index(str, ':') ? AF_INET6 : AF_INET;
    char *addr_str = strtok(str, delim);
    char *port_str = strtok(NULL, delim);
    int portNum = atoi(port_str);
    if(portNum > 0
       && portNum < 655356
       && parseNumericAddress(addr_str, NULL, addr, family)) {
      *p_port = portNum;
      return YES;
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________   processCommandLine      __________________
    -----------------___________________________------------------
  */

  static void instructions(char *command)
  {
    fprintf(stderr,"Usage: %s -s IPSRC:SRCPORT -d IPDST:DSTPORT -i IFINDEX [-U] [-D]\n", command);
    exit(-1);
  }
  
  static void processCommandLine(IND *ind, int argc, char *argv[])
  {
    int in;
    while ((in = getopt(argc, argv, "s:d:i:UD")) != -1) {
      switch(in) {
      case 's':
	if(!parseSocket(optarg, &ind->src, &ind->sport)) {
	  fprintf(stderr, "bad source socket format\n");
	  exit(-1);
	}
	break;
      case 'd':
	if(!parseSocket(optarg, &ind->dst, &ind->dport)) {
	  fprintf(stderr, "bad destination socket format\n");
	  exit(-1);
	}
	break;
      case 'i':
	ind->ifIndex = atoi(optarg);
	break;
      case 'U':
	ind->udp = YES;
	break;
      case 'D':
	ind->dump = YES;
	break;
      case '?':
      case 'h':
      default: instructions(*argv);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________           main            __________________
    -----------------___________________________------------------
  */

  int main(int argc, char **argv) {
    IND *ind = calloc(1, sizeof(IND));
    if(getuid() != 0) {
      fprintf(stderr, "must be ROOT to run this program\n");
      exit(-1);
    }
    // parse args
    processCommandLine(ind, argc, argv);
    // open netlink socket
    myLog("open netlink...");
    ind->nl_sock = UTNLDiag_open();
    if(ind->nl_sock < 0) {
      myLog("UTNLDiag_open failed : %s", strerror(errno));
      exit(-1);
    }
    myLog("send request...");
    lookup_sample(ind, &ind->src, &ind->dst, ind->udp, ind->sport, ind->dport, ind->ifIndex);
    myLog("read...");
    socketRead(ind, 500, readNetlink_DIAG);

    return 0;
  }
