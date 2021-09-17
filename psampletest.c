/* This software is distributed under the following license:
 * http://sflow.net/license.html
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

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#define PST_PSAMPLE_READNL_RCV_BUF 8192
#define PST_PSAMPLE_READNL_BATCH 100
#define PST_PSAMPLE_RCVBUF 8000000

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
  } EnumHSPPsampleAttributes;
  
  typedef struct _PST {
    uint32_t id;
    int nl_sock;
    uint32_t nl_seq;
    uint32_t genetlink_version;
    uint16_t family_id;
    uint32_t group_id;
    // psample channel groups
    uint32_t grp_ingress;
    uint32_t grp_egress;
  } PST;

  /*_________________---------------------------__________________
    _________________       fcntl utils         __________________
    -----------------___________________________------------------
  */
  static void setNonBlocking(int fd) {
    // set the socket to non-blocking
    int fdFlags = fcntl(fd, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, fdFlags) < 0) {
      printf("fcntl(O_NONBLOCK) failed: %s\n", strerror(errno));
    }
  }

  static void setCloseOnExec(int fd) {
    // make sure it doesn't get inherited, e.g. when we fork a script
    int fdFlags = fcntl(fd, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(fd, F_SETFD, fdFlags) < 0) {
      printf("fcntl(F_SETFD=FD_CLOEXEC) failed: %s\n", strerror(errno));
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
      printf("nl_sock open failed: %s\n", strerror(errno));
      return -1;
    }

    // bind to a suitable id
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
			      .nl_pid = UTNLGeneric_pid(mod_id) };
    if(bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
      printf("UTNLGeneric_open: bind failed: %s\n", strerror(errno));

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
    _________________    getFamily_PSAMPLE      __________________
    -----------------___________________________------------------
  */

  static void getFamily_PSAMPLE(PST *pst)
  {
    printf("pstest: getFamily\n");
    UTNLGeneric_send(pst->nl_sock,
		     pst->id,
		     GENL_ID_CTRL,
		     CTRL_CMD_GETFAMILY,
		     CTRL_ATTR_FAMILY_NAME,
		     PSAMPLE_GENL_NAME,
		     sizeof(PSAMPLE_GENL_NAME)+1,
		     ++pst->nl_seq);
  }

  /*_________________---------------------------__________________
    _________________    joinGroup_PSAMPLE      __________________
    -----------------___________________________------------------
  */

  static void joinGroup_PSAMPLE(PST *pst)
  {
    printf("pstest: joinGroup %u\n", pst->group_id);
    // register for the multicast group_id
    if(setsockopt(pst->nl_sock,
		  SOL_NETLINK,
		  NETLINK_ADD_MEMBERSHIP,
		  &pst->group_id,
		  sizeof(pst->group_id)) == -1) {
      printf("error joining PSAMPLE netlink group %u : %s\n",
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
    printf("generic netlink CMD = %u\n", genl->cmd);

    for(int offset = GENL_HDRLEN; offset < msglen; ) {
      struct nlattr *attr = (struct nlattr *)(msg + offset);
      if(attr->nla_len == 0 ||
	 (attr->nla_len + offset) > msglen) {
	printf("processNetlink_GENERIC attr parse error");
	break; // attr parse error
      }
      char *attr_datap = (char *)attr + NLA_HDRLEN;
      switch(attr->nla_type) {
      case CTRL_ATTR_VERSION:
	pst->genetlink_version = *(uint32_t *)attr_datap;
	break;
      case CTRL_ATTR_FAMILY_ID:
	pst->family_id = *(uint16_t *)attr_datap;
	printf("generic family id: %u\n", pst->family_id); 
	break;
      case CTRL_ATTR_FAMILY_NAME:
	printf("generic family name: %s\n", attr_datap); 
	break;
      case CTRL_ATTR_MCAST_GROUPS:
	for(int grp_offset = NLA_HDRLEN; grp_offset < attr->nla_len;) {
	  struct nlattr *grp_attr = (struct nlattr *)(msg + offset + grp_offset);
	  if(grp_attr->nla_len == 0 ||
	     (grp_attr->nla_len + grp_offset) > attr->nla_len) {
	    printf("processNetlink_GENERIC grp_attr parse error\n");
	    break;
	  }
	  char *grp_name=NULL;
	  uint32_t grp_id=0;
	  for(int gf_offset = NLA_HDRLEN; gf_offset < grp_attr->nla_len; ) {
	    struct nlattr *gf_attr = (struct nlattr *)(msg + offset + grp_offset + gf_offset);
	    if(gf_attr->nla_len == 0 ||
	       (gf_attr->nla_len + gf_offset) > grp_attr->nla_len) {
	      printf("processNetlink_GENERIC gf_attr parse error\n");
	      break;
	    }
	    char *grp_attr_datap = (char *)gf_attr + NLA_HDRLEN;
	    switch(gf_attr->nla_type) {
	    case CTRL_ATTR_MCAST_GRP_NAME:
	      grp_name = grp_attr_datap;
	      printf("pstest: psample multicast group: %s\n", grp_name); 
	      break;
	    case CTRL_ATTR_MCAST_GRP_ID:
	      grp_id = *(uint32_t *)grp_attr_datap;
	      printf("pstest: psample multicast group id: %u\n", grp_id); 
	      break;
	    }
	    gf_offset += NLMSG_ALIGN(gf_attr->nla_len);
	  }
	  if(pst->group_id == 0
	     && grp_name
	     && grp_id
	     && !strcmp(grp_name, PSAMPLE_NL_MCGRP_SAMPLE_NAME)) {
	    printf("pstest: psample found group %s=%u\n", grp_name, grp_id);
	    pst->group_id = grp_id;
	    joinGroup_PSAMPLE(pst);
	  }

	  grp_offset += NLMSG_ALIGN(grp_attr->nla_len);
	}
	break;
      default:
	printf("pstest: psample attr type: %u (nested=%u) len: %u\n",
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
    printf("pstest: psample netlink (type=%u) CMD = %u\n", nlh->nlmsg_type, genl->cmd);

    uint16_t ifin=0,ifout=0;
    uint32_t pkt_len=0;
    uint32_t grp_no=0;
    uint32_t grp_seq=0;
    uint32_t sample_n=0;
    uint16_t e_queue=0;
    uint64_t e_depth=0;
    uint64_t e_delay=0;
    u_char *pkt=NULL;

    // TODO: tunnel encap/decap may be avaiable too

    for(int offset = GENL_HDRLEN; offset < msglen; ) {
      struct nlattr *ps_attr = (struct nlattr *)(msg + offset);
      if(ps_attr->nla_len == 0 ||
	 (ps_attr->nla_len + offset) > msglen) {
	printf("processNetlink_PSAMPLE attr parse error");
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
      case PSAMPLE_ATTR_DATA: pkt = datap; break;
      case PST_PSAMPLE_ATTR_OUT_TC: e_queue = *(uint16_t *)datap; break;
      case PST_PSAMPLE_ATTR_OUT_TC_OCC: e_depth = *(uint64_t *)datap; break;
      case PST_PSAMPLE_ATTR_LATENCY: e_delay = *(uint64_t *)datap; break;
      }
      offset += NLMSG_ALIGN(ps_attr->nla_len);
    }

    printf("pstest: grp=%u in=%u out=%u n=%u seq=%u pktlen=%u pkt=%p q=%u depth=%"PRIu64" delay=%"PRIu64"\n",
	    grp_no,
	    ifin,
	    ifout,
	    sample_n,
	    grp_seq,
	    pkt_len,
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
	    printf("received Netlink ACK");
	  }
	  else {
	    // TODO: parse NLMSGERR_ATTR_OFFS to get offset?  Might be helpful
	    printf("pstest: error in netlink message: %d : %s\n",
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
    _________________    send_test_msg          __________________
    -----------------___________________________------------------
  */

  static void send_test_msg(PST *pst) {
    printf("pstest: send_test_msg getuid=%d geteuid=%d\n", getuid(), geteuid());

    struct nlmsghdr nlh = { };
    struct genlmsghdr ge = { };
    struct nlattr attr_psgid = { };
    uint32_t psgid = pst->grp_ingress;
    int psgid_footprint = NLMSG_ALIGN(sizeof(psgid));
    attr_psgid.nla_len = sizeof(attr_psgid) + sizeof(psgid);
    attr_psgid.nla_type = PSAMPLE_ATTR_SAMPLE_GROUP;

    ge.cmd = PSAMPLE_CMD_SAMPLE;
    ge.version = PSAMPLE_GENL_VERSION;

    nlh.nlmsg_len = NLMSG_LENGTH(psgid_footprint + sizeof(attr_psgid) + sizeof(ge));
    nlh.nlmsg_flags = 0;
    nlh.nlmsg_type = pst->family_id;
    nlh.nlmsg_seq = ++pst->nl_seq;
    nlh.nlmsg_pid = UTNLGeneric_pid(pst->id);

#define MY_IOV_FRAGMENTS 4
    
    struct iovec iov[MY_IOV_FRAGMENTS] = {
      { .iov_base = &nlh,         .iov_len = sizeof(nlh) },
      { .iov_base = &ge,          .iov_len = sizeof(ge) },
      { .iov_base = &attr_psgid,  .iov_len = sizeof(attr_psgid) },
      { .iov_base = &psgid,       .iov_len = psgid_footprint }
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
			      .nl_groups = (1 << (pst->group_id-1)) };

    struct msghdr msg = { .msg_name = &sa,
			  .msg_namelen = sizeof(sa),
			  .msg_iov = iov,
			  .msg_iovlen = MY_IOV_FRAGMENTS };

    int status = sendmsg(pst->nl_sock, &msg, 0);
    if(status <= 0)
      printf("pstest: send returned %d : %s\n", status, strerror(errno));
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
	printf("pselect() returned %d : %s\n", nfds, strerror(errno));
	abort();
      }
    }
  }
  
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
    pst->id = 0;
    pst->nl_sock = UTNLGeneric_open(pst->id);
    if(pst->nl_sock < 0) {
      printf("pstest: myNLGeneric_open failed : %s\n", strerror(errno));
      exit(-1);
    }

    printf("pstest: netlink socket number = %u\n", UTNLGeneric_pid(pst->id));
    // kick off with the family lookup request
    getFamily_PSAMPLE(pst);
    // wait some number of mS for answer
    socketRead(pst, 500, readNetlink_PSAMPLE);
    if(pst->family_id == 0) {
      printf("failed to get PSAMPLE family id\n");
      exit(-1);
    }
    
    // join multicast group TODO: is this necessary?
    joinGroup_PSAMPLE(pst);
    send_test_msg(pst);
    // read loop
    for(;;) {
      socketRead(pst, 1000, readNetlink_PSAMPLE);
    }
  }
