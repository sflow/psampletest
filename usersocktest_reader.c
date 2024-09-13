#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define NLINK_MSG_LEN 1024
#define NETLINK_USER 31

int main(int argc, char **argv) {
  //int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
  //int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
  printf("Inside recv main\n");

  if (fd < 0) {
    printf("Socket creation failed. try again\n");
    return -1;
  }

  struct sockaddr_nl src_addr;
  memset(&src_addr, 0, sizeof(src_addr));

  //allocate buffer for netlink message which is message header + message payload
  struct nlmsghdr *nlh =(struct nlmsghdr *) malloc(NLMSG_SPACE(NLINK_MSG_LEN));
  memset(nlh, 0, NLMSG_SPACE(NLINK_MSG_LEN));

  //fill the iovec structure
  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  //define the message header for message
  //sending
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));

  //int sender_pid;
  printf("Receiver process id: %d\n", getpid());
  
  src_addr.nl_family = AF_NETLINK;      //AF_NETLINK socket protocol
  src_addr.nl_pid =  6343; // getpid();  //application unique id
  // src_addr.nl_groups = 0;    //specify not a multicast communication

  nlh->nlmsg_len = NLMSG_SPACE(NLINK_MSG_LEN);   //netlink message length 
  nlh->nlmsg_pid = 0; // getpid();            //src application unique id
  nlh->nlmsg_flags = 0;

  iov.iov_base = (void *)nlh;     //netlink message header base address
  iov.iov_len = nlh->nlmsg_len;   //netlink message length
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  //attach socket to unique id or address
  if(bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
    printf("Bind failed");
    return -1;
  }

#if TRY_MULTICAST
  // join multicast group
  int mgroup = 21;
  if(setsockopt(fd,
		SOL_NETLINK,
		NETLINK_ADD_MEMBERSHIP,
		&mgroup,
		sizeof(mgroup)) == -1) {
    fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
  }
#endif

  /* Listen forever in a while loop */
  while (1) {
    //receive the message
    recvmsg(fd, &msg, 0);
    printf("Received message: %s\n", (char *)NLMSG_DATA(nlh));
  }
  close(fd); // close the socket
}
