#include <iostream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <poll.h>
#include <cstdlib>
#include <netinet/icmp6.h>




//#define DEBUG
#ifdef DEBUG
#define DEB(x) do{\
  std::cerr<< x;}\
  while(0)
#endif

#ifndef DEBUG
#define DEB(X)
#endif

using namespace std;

const int ONE = 1;
const int WAIT_TIME = 2;
char MAX_TTL = 30;
const char * PORT = "33434";


//parsing arguments
int ParseArgs(char** argv,int argc,char &max_ttl,char &ttl, char * &dest_addr){
  int arg_count = 2;
  for(int i =1;i<argc;i++){
    DEB("arg["<<i<<"] = "<<argv[i]<<endl);
	//checking for '-f' argument
    if (!strcmp(argv[i], "-f")) {
      DEB("WE FIND '-f'!");
	  if(i+1 == argc) return -1;
      ttl = static_cast<char>(atoi(argv[i+1]));
	  arg_count +=2;
    }
	//checking for '-m' argument
    else if (!strcmp(argv[i], "-m")) {
      DEB("WE FIND '-m'!");
	  if(i+1 == argc) return -1;
      max_ttl = static_cast<char>(atoi(argv[i+1]));
	  arg_count+=2;
    }
  }
  //control arguments count
  if(arg_count != argc)
	return -1;
  dest_addr = argv[argc-1];
  return 0;
}

int main (int argc, char *argv[])
{
  char ttl = 1;
  char * dest_addr;
  if(ParseArgs(argv, argc, MAX_TTL, ttl, dest_addr) == -1){
  	cerr<<"Wrong programm arguments\n";
  	return -1;
  }
  //set version of ip protocol
  bool prot_ver6 = string(dest_addr).find(':') == string::npos ? 0 : 1;


  struct timeval ts,tf;
  struct timezone tz;
  if (argc >6  || argc < 2){
      cerr<<"Wrong parameters"<<endl;
      exit (-1);
  }

  int send_sock = 0;
  auto af = AF_INET;
  if(prot_ver6) af = AF_INET6;
  if ((send_sock = socket (af, SOCK_DGRAM, 0)) <= 0){
   cerr<< "ERROR: creating send socket"<<"\n";
   exit(-1);
  }
  char buf[100] = { 0 };



  struct addrinfo hints, *servinfo;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = af;
  if ( getaddrinfo(dest_addr, PORT, &hints, &servinfo) != 0){
        cerr << argv[0] << ": getaddrinfo error"<<  endl;
    		return -1;
  }
  if (servinfo == NULL) {
		cerr << " addrinfo error" << endl;
		return -1;
	}

  // inet_pton (AF_INET, dest_addr, &(addr.sin_addr));
  if(prot_ver6){
    if(setsockopt(send_sock, IPPROTO_IPV6, IPV6_RECVERR, &ONE,sizeof(ONE))){
      cerr<<"ERROR: can't set IP_RECVERR option for socket\n";
      close(send_sock);
      exit(-1);
    }
  }
  else{
    if(setsockopt(send_sock, IPPROTO_IP, IP_RECVERR, &ONE,sizeof(ONE))){
      cerr<<"ERROR: can't set IP_RECVERR option for socket\n";
      close(send_sock);
      exit(-1);
    }
  }
  struct pollfd fds;
  fds.fd = send_sock;
  fds.events = 0;
  int result = 0;

  union sock_union{
    struct sockaddr_in6 v6;
    struct sockaddr_in v4;
  };
  union icmp_hdr_union{
    struct icmp6_hdr v6;
    struct icmphdr v4;
  };
  int counter =1;


  while (ttl <= MAX_TTL)
  {
      if(prot_ver6){
        int ttl_int = (int  )ttl;
        if(setsockopt(send_sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &(ttl_int),sizeof(ttl_int))){
          cerr<<"ERROR: can't set IP_TTL option for socket\n";
          close(send_sock);
          exit(-1);
        }
      }
      else{
        if(setsockopt(send_sock, IPPROTO_IP, IP_TTL, &(ttl),sizeof(ttl))){
          cerr<<"ERROR: can't set IP_TTL option for socket\n";
          close(send_sock);
          exit(-1);
        }
      }


      DEB("Start sending"<<endl);
      // sendto (send_sock, buf, 0, 0, (struct sockaddr*) &addr, sizeof addr);
      sendto(send_sock, "",	0, 0, servinfo->ai_addr, servinfo->ai_addrlen);
      gettimeofday(&ts, &tz);


      char buff[1024] = { 0 };
      struct iovec iov;
      sock_union addr2;
      sock_union remote;
      icmp_hdr_union icmphd2;
      struct msghdr msg;
      struct cmsghdr *cmsg;
      struct sock_extended_err *sock_err;
      char buffer[1024] {0};
      if(prot_ver6){
        // struct sockaddr_in6 addr2;
        // struct sockaddr_in6 remote;
        // struct icmp6_hdr icmphd2;
        iov.iov_len = sizeof(struct icmp6_hdr);
        iov.iov_base = &(icmphd2.v6);
        msg.msg_name = (void*)&(remote.v6);
        msg.msg_namelen = sizeof(remote.v6);
      }
      else{
        iov.iov_len = sizeof(struct icmphdr);
        iov.iov_base = &(icmphd2.v4);
        msg.msg_name = (void*)&(remote.v4);
        msg.msg_namelen = sizeof(remote.v4);
      }
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_flags = 0;
      msg.msg_control = buffer;
      msg.msg_controllen = sizeof(buffer);


      //seting timer and wait for response
      result = poll(&fds,1,WAIT_TIME*1000);
      switch (result ) {
        case 0:
          DEB("No response were recieved, timeout expired\n");
          fprintf(stdout, "%2d   *\n",counter);
          ttl++;
		  counter++;
          continue;
          break;
        case -1:
          ttl++;
          DEB("error was occured!\n");
		  counter++;
          continue;
          break;
        default:
          DEB("Everything seems fine\n");
      }
      result = recvmsg(send_sock, &msg, MSG_ERRQUEUE);
      gettimeofday(&tf, &tz);
      double time_delta= (tf.tv_sec-ts.tv_sec) * 1000 + double(tf.tv_usec - ts.tv_usec)/1000;
      for (cmsg = CMSG_FIRSTHDR(&msg);cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg))
      {
        if (cmsg->cmsg_level == SOL_IPV6 || cmsg->cmsg_level == SOL_IP)
        {
          if (cmsg->cmsg_type == IPV6_RECVERR || cmsg->cmsg_type == IP_RECVERR )
          {
            DEB("We got IP_RECVERR message\n");
            sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
            if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP6)
            {
              char response_source_addr[50]{0};
              struct sockaddr_in6 * source_addr =(struct sockaddr_in6 *) SO_EE_OFFENDER(sock_err);
              inet_ntop(AF_INET6, &(source_addr->sin6_addr), response_source_addr, sizeof(response_source_addr));
              DEB("err type: "<<(int)sock_err->ee_type<<" err code:"<<(int)sock_err->ee_type<<" response_source_addr: "<<response_source_addr<<endl);

              //converting target host addr to string
              char hostname[50]{0};
              char servname[50]  {0};
              string str_host_name{""};
              if(getnameinfo((const sockaddr *)source_addr,sizeof(*source_addr),hostname,50,servname,50,0)== 0)
              {
                 str_host_name+=hostname;
                 str_host_name+=" (";
                 str_host_name+=response_source_addr;
                 str_host_name+=")";
              }
              else str_host_name+=response_source_addr;

              // TTL was exceeded
              if(sock_err->ee_type == ICMP6_TIME_EXCEEDED &&
                 sock_err->ee_code == ICMP6_TIME_EXCEED_TRANSIT)
              {
                fprintf(stdout, "%2d   %s   %.3f ms\n",counter,str_host_name.c_str(),time_delta );
                DEB( "ICMP time exceeded Error\n");
              }
              else if(sock_err->ee_type == ICMP6_DST_UNREACH){
                switch(sock_err->ee_code)
                {
                  //Network Unreachable
                  case ICMP6_DST_UNREACH_NOROUTE:
                      DEB( "Network Unreachable Error\n");
                      fprintf(stdout, "%2d   N!\n",counter);
                      break;
                  //Protocol Unreachable
                  case ICMP6_DST_UNREACH_BEYONDSCOPE:
                      DEB("Host Unreachable Error\n");
                      fprintf(stdout, "%2d   H!\n",counter);
                      break;
                  //host Unreachable
                  case ICMP6_DST_UNREACH_ADDR	:
                      DEB( "Protocol Unreachable Error\n");
                      fprintf(stdout, "%2d   P!\n",counter);
                      break;
                  //communication administratively prohibited
                  case ICMP6_DST_UNREACH_ADMIN:
                      DEB( "Communication Administratively Prohibited\n");
                      fprintf(stdout, "%2d   X!\n",counter);
                      break;
                  //Packet reachead
                  case ICMP6_DST_UNREACH_NOPORT :
                      fprintf(stdout, "%2d   %s   %.3f ms\n",counter,str_host_name.c_str(),time_delta );
                      DEB("Packet reached destination!\n");
                      close(send_sock);
                      exit(0);
                      break;
                  default:
                    cerr<<"Unknown error\n";
                }
              }
            }
            else if(sock_err->ee_origin == SO_EE_ORIGIN_ICMP)
            {
              char response_source_addr[50]{0};
              struct sockaddr_in * source_addr =(struct sockaddr_in *) SO_EE_OFFENDER(sock_err);
              inet_ntop(AF_INET, &(source_addr->sin_addr), response_source_addr, sizeof(response_source_addr));
              DEB("err type: "<<(int)sock_err->ee_type<<" err code:"<<(int)sock_err->ee_type<<" response_source_addr: "<<response_source_addr<<endl);

              //converting target host addr to string
              char hostname[50]{0};
              char servname[50]  {0};
              string str_host_name{""};
              if(getnameinfo((const sockaddr *)source_addr,sizeof(*source_addr),hostname,50,servname,50,0)== 0)
              {
                str_host_name+=hostname;
                str_host_name+=" (";
                str_host_name+=response_source_addr;
                str_host_name+=")";
              }
              else str_host_name+=response_source_addr;


              // TTL was exceeded
              if(sock_err->ee_type == ICMP_TIME_EXCEEDED && sock_err->ee_code == ICMP_EXC_TTL)
              {
                fprintf(stdout, "%2d   %s   %.3f ms\n",counter,str_host_name.c_str(),time_delta );
                DEB( "ICMP time exceeded Error\n");
              }
              else if(sock_err->ee_type == ICMP_DEST_UNREACH){
                switch (sock_err->ee_code)
                {
                  case ICMP_NET_UNREACH:
                      DEB( "Network Unreachable Error\n");
                      fprintf(stdout, "%2d   N!\n",counter);
                      break;
                  case ICMP_HOST_UNREACH:
                      DEB("Host Unreachable Error\n");
                      fprintf(stdout, "%2d   H!\n",counter);
                      break;
                  case ICMP_PROT_UNREACH:
                      DEB( "Protocol Unreachable Error\n");
                      fprintf(stdout, "%2d   P!\n",counter);
                      break;
                  //communication administratively prohibited
                  case ICMP_PKT_FILTERED:
                      DEB( "Communication Administratively Prohibited\n");
                      fprintf(stdout, "%2d   X!\n",counter);
                      break;
                  //Packet reachead destination
                  case ICMP_PORT_UNREACH :
                      fprintf(stdout, "%2d   %s   %.3f ms\n",counter,str_host_name.c_str(),time_delta );
                      DEB("Packet reached destination!\n");
                      close(send_sock);
                      exit(0);
                      break;
                  default:
                    cerr<<"Unknown error\n";
                }
              }
            }
            break;
          }
        }
      }
      ttl++;
	  counter++;
    }

  DEB("TTL limit reached!\n");
  close(send_sock);

  return 0;
}
