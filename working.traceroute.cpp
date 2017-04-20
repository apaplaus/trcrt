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




#define DEBUG
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

// void  GetIp(){
//   char buffer[34]{0};
//   int buflen=34;
//    int sock = socket(AF_INET, SOCK_DGRAM, 0);
//
//    const char* kGoogleDnsIp = "8.8.8.8";
//    uint16_t kDnsPort = 53;
//    struct sockaddr_in serv;
//    memset(&serv, 0, sizeof(serv));
//    serv.sin_family = AF_INET;
//    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
//    serv.sin_port = htons(kDnsPort);
//
//    int err = connect(sock, (const sockaddr*) &serv, sizeof(serv));
//
//    sockaddr_in name;
//    socklen_t namelen = sizeof(name);
//    err = getsockname(sock, (sockaddr*) &name, &namelen);
//
//    const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, buflen);
//
//    cout<<"address: "<<p<<endl;
//    close(sock);
// }

// string ConvertToBin(char ch){
//   string result {};
//   for(int i =7;i>=0;i--){
//     result.append(1, (ch>>i & 0x1) + '0');
//   }
//   return result;
// }

//parsing arguments
int ParseArgs(char** argv,int argc,char &max_ttl,char &ttl, char * &dest_addr){
  for(int i =1;i<argc;i++){
    DEB("arg["<<i<<"] = "<<argv[i]<<endl);
    if (!strcmp(argv[i], "-f")) {
      DEB("WE FIND '-f'!");
      ttl = static_cast<char>(atoi(argv[i+1]));
    }
    else if (!strcmp(argv[i], "-m")) {
      DEB("WE FIND '-m'!");
      max_ttl = static_cast<char>(atoi(argv[i+1]));
    }
  }
  dest_addr = argv[argc-1];
  return 0;
}

int main (int argc, char *argv[])
{
  char ttl = 1;
  char * dest_addr;
  ParseArgs(argv, argc, MAX_TTL, ttl, dest_addr);

  struct timeval ts,tf;
  struct timezone tz;
  if (argc >6  || argc < 2){
      cerr<<"Wrong parameters"<<endl;
      exit (-1);
  }

  int send_sock = 0;
  // if ((send_sock = socket (AF_INET, SOCK_DGRAM, 0)) <= 0){
  //  cerr<< "ERROR: creating send socket"<<"\n";
  //  exit(-1);
  // }
  // char buf[100] = { 0 };
  // if (setsockopt(send_sock, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE)) == -1) {
  //   cerr<<"Error:setsockopt";
  //   exit(-1);
  // }


  // struct sockaddr_in addr;
  // addr.sin_port = htons (6677);
  // addr.sin_family = AF_INET;
  struct addrinfo hints, *servinfo;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  if ( getaddrinfo(dest_addr, "33434", &hints, &servinfo) != 0){
        cerr << argv[0] << ": getaddrinfo error"<<  endl;
    		return -1;
  }
  if (servinfo == NULL) {
		cerr << " addrinfo error" << endl;
		return -1;
	}

  // inet_pton (AF_INET, dest_addr, &(addr.sin_addr));
  // if(setsockopt(send_sock, IPPROTO_IP, IP_RECVERR, &ONE,sizeof(ONE))){
  //   cerr<<"ERROR: can't set IP_RECVERR option for socket\n";
  //   close(send_sock);
  //   exit(-1);
  // }

  struct pollfd fds;
  // fds.fd = send_sock;
  fds.events = 0;
  int result = 0;

  while (ttl <= MAX_TTL)
    {
      //creating new socket
      if ((send_sock = socket (AF_INET, SOCK_DGRAM, 0)) <= 0){
       cerr<< "ERROR: creating send socket"<<"\n";
       exit(-1);
      }
      if(setsockopt(send_sock, IPPROTO_IP, IP_RECVERR, &ONE,sizeof(ONE))){
        cerr<<"ERROR: can't set IP_RECVERR option for socket\n";
        close(send_sock);
        exit(-1);
      }
      fds.fd = send_sock;

      if(setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl,sizeof(ttl))){
        cerr<<"ERROR: can't set IP_TTL option for socket\n";
        close(send_sock);
        exit(-1);
      }


      DEB("Start sending"<<endl);
      // sendto (send_sock, buf, 0, 0, (struct sockaddr*) &addr, sizeof addr);
      sendto(send_sock, "",	0, 0, servinfo->ai_addr, servinfo->ai_addrlen);
      gettimeofday(&ts, &tz);


      char buff[1024] = { 0 };
      struct sockaddr_in addr2;
      struct icmphdr *icmphd2 = (struct icmphdr *) (buff + 20);
      struct msghdr msg;
      struct cmsghdr *cmsg;
      struct sock_extended_err *sock_err;
      char buffer[1024] {0};
      struct iovec iov;
      struct sockaddr_in remote;
      iov.iov_base = &icmphd2;
      iov.iov_len = sizeof(struct icmphdr);
      msg.msg_name = (void*)&remote;
      msg.msg_namelen = sizeof(remote);
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
          cout<<static_cast<int>(ttl)<<"   *\n";
          ttl++;
          continue;
          break;
        case -1:
          ttl++;
          DEB("error was occured!\n");
          continue;
          break;
        default:
          DEB("Everything seems fine\n");
      }
      result = recvmsg(send_sock, &msg, MSG_ERRQUEUE);
      gettimeofday(&tf, &tz);
      double time_delta= (tf.tv_sec-ts.tv_sec) * 1000 + (tf.tv_usec - ts.tv_usec)/1000;
      for (cmsg = CMSG_FIRSTHDR(&msg);cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg))
      {
        if (cmsg->cmsg_level == SOL_IP || cmsg->cmsg_level == IPPROTO_IP)
        {
          if (cmsg->cmsg_type == IP_RECVERR)
          {
            DEB("We got IP_RECVERR message\n");
            sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
            if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP)
            {
              char response_source_addr[40]{0};
              struct sockaddr_in * source_addr =(struct sockaddr_in *) SO_EE_OFFENDER(sock_err);
              inet_ntop(AF_INET, &(source_addr->sin_addr), response_source_addr, sizeof(response_source_addr));
              DEB("err type: "<<(int)sock_err->ee_type<<" err code:"<<(int)sock_err->ee_type<<" response_source_addr: "<<response_source_addr<<endl);
              fprintf(stdout, "%d   %s   %.3f ms\n",ttl,response_source_addr,time_delta );
              switch (sock_err->ee_type)
              {
                case ICMP_NET_UNREACH:
                    DEB( "Network Unreachable Error\n");
                    break;
                case ICMP_HOST_UNREACH:
                    DEB("Host Unreachable Error\n");
                    break;
                case ICMP_PROT_UNREACH:
                    DEB( "Protocol Unreachable Error\n");
                    break;
                // TTL was exceeded
                case ICMP_TIME_EXCEEDED    :
                    DEB( "ICMP time exceeded Error\n");
                    break;
                //Packet reachead
                case ICMP_PORT_UNREACH :
                    cerr<<"Packet reached destination!\n";
                    break;
                default:
                  cerr<<"Default branch\n";
                /* Handle all other cases. Find more errors :
                 * http://lxr.linux.no/linux+v3.5/include/linux/icmp.h#L39
                 */
              }
            }
            break;
          }
        }
      }
      close(send_sock);
      ttl++;
    }

  cerr<<"TTL limit reached!\n";
  close(send_sock);

  return 0;
}
