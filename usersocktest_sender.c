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
  printf("Inside send main\n");

  if (fd < 0) {
    printf("Socket creation failed. try again\n");
    return -1;
  }

  /* Declare for src NL sockaddr, dest NL sockaddr, nlmsghdr, iov, msghr */
  struct sockaddr_nl dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));

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

  // int receiver_pid;
  printf("Sender process id: %d\n", getpid());

  dest_addr.nl_family = AF_NETLINK;        // protocol family
  dest_addr.nl_pid = 6343; //receiver_pid; // destination process id
  // dest_addr.nl_groups = 0; 

  nlh->nlmsg_len = NLMSG_SPACE(NLINK_MSG_LEN);  //netlink message length 
  nlh->nlmsg_pid = getpid();           //src application unique id
  nlh->nlmsg_flags = 0;
  strcpy(NLMSG_DATA(nlh), "Hello World !");   //copy the payload to be sent

  iov.iov_base = (void *)nlh;     //netlink message header base address
  iov.iov_len = nlh->nlmsg_len;   //netlink message length
  msg.msg_name = (void *)&dest_addr;
  msg.msg_namelen = sizeof(dest_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

#ifdef TRY_MULTICAST
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
  
  //send the message
  sendmsg(fd, &msg, 0);
  printf("Send message %s\n", (char *)NLMSG_DATA(nlh));

  close(fd); // close the socket
}
