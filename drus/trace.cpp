#include <iostream>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <poll.h>

#include <linux/icmp.h>
#include <linux/errqueue.h>

#define MAXBUFLEN 1024

using std::cout;
using std::cerr;
using std::endl;
using std::string;

const char *g_port_num = "33434"; //"33434"

const int g_exit_code_bad_arg    = 1;
const int g_exit_code_sock_error = 2;
const int g_exit_code_addrinfo   = 3;
const int g_exit_code_sendto     = 4;
const int g_exit_code_recvfrom   = 5;
const int g_exit_code_poll       = 6;
const int g_exit_code_recvmsg    = 7;


struct trace_opts {
	int first_ttl;
	int max_ttl;
	const char *addr_present;
	bool ipv6mode; /* if ipv6 address was passed */
};

void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	} else {
		return &(((struct sockaddr_in6*)sa)->sin6_addr);
	}
}

string get_addr_str_represent(struct sockaddr_storage *addr)
{
	char s[INET6_ADDRSTRLEN];
	const void *dst = inet_ntop(
		addr->ss_family,
		get_in_addr((struct sockaddr *)addr),
		s,
		sizeof s
	);

	if (dst == NULL) {
		perror("inet_ntop");
	}	

	return string(s);
}

struct trace_opts parse_program_args(int argc, char **argv)
{
	struct trace_opts args = { -1, -1, NULL, false };
	int tmp = 0;
	while (-1 != tmp) {
		tmp = getopt(argc, argv, "m:f:");
		switch (tmp) {
		case 'm':
			try {
				args.max_ttl = std::stoi(optarg);
			} catch (...) {
				throw ": cannot convert -m optarg to int representation";
			}

			break;
		case 'f':
			try {
				args.first_ttl = std::stoi(optarg);
			} catch (...) {
				throw ": cannot convert -f optarg to int representation";
			}

			break;
		case '?':
			exit(1);
			break;
		default:
			if (optind == argc) {
				throw ": you should specify remote address";
			}

			args.ipv6mode = false;
				args.addr_present = argv[optind];
			// int tmp;
			// if (inet_pton(AF_INET, argv[optind], &tmp)) {
			// 	args.ipv6mode = false;
			// 	args.addr_present = argv[optind];
			// 	break;
			// }

			// if (inet_pton(AF_INET6, argv[optind], &tmp)) {
			// 	args.ipv6mode = true;
			// 	args.addr_present = argv[optind];
			// 	break;
			// }

			// throw ": bad format of ip address";
			break;
		}
	}

	if (args.first_ttl == -1) {
		args.first_ttl = 1;
	}

	if (args.max_ttl == -1) {
		args.max_ttl = 30;
	}
	return args;
}

int ttl_socket(int ttl, bool ipv6mode)
{
	int domain;
	if (ipv6mode) {
		domain = AF_INET6;
	} else {
		domain = AF_INET;
	}

	int sock;
	if (-1 == (sock = socket(domain, SOCK_DGRAM, IPPROTO_UDP))) {
		throw ": socket error";
	}

	if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl)) {
		throw ": setsockopt IP_TTL error";
	}
// new
	int yes = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_RECVERR, &yes, sizeof(yes))) {
		throw ": setsockopt IP_RECVERR error";
	}
	return sock;
// end new
}

int get_icmp_code(struct cmsghdr *cmsg, struct sockaddr_storage *addr_p)
{
	struct sock_extended_err *sock_err;
	sock_err = (struct sock_extended_err *)CMSG_DATA(cmsg);
	if (sock_err)
	{
		/* We are intrested in ICMP errors */
		if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP) 
		{
			*addr_p = 
				*(struct sockaddr_storage *)SO_EE_OFFENDER(sock_err);
			return sock_err->ee_type;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	struct trace_opts trace_opts;
	try {
		trace_opts = parse_program_args(argc, argv);
	} catch (const char *err_msg) {
		cerr << argv[0] << err_msg << endl;
		return g_exit_code_bad_arg;
	}

	struct addrinfo hints, *servinfo;
	memset(&hints, 0, sizeof hints);
	if (trace_opts.ipv6mode) {
		hints.ai_family = AF_INET6;
	} else {
		hints.ai_family = AF_INET;
	}

	int rv;
	rv = getaddrinfo(trace_opts.addr_present,
			g_port_num, &hints, &servinfo);

	if (rv != 0) {
		cerr << argv[0] << ": " << gai_strerror(rv) << endl;
		return g_exit_code_addrinfo;
	}

	if (servinfo == NULL) {
		cerr << argv[0] << ": addrinfo error" << endl;
		return g_exit_code_addrinfo;
	}

	bool done = false;
	while (trace_opts.first_ttl <= trace_opts.max_ttl && !done) {
		int send_sock;
		try {
			send_sock = ttl_socket(trace_opts.first_ttl,
					trace_opts.ipv6mode);
		} catch (const char *err_msg) {
			cerr << argv[0] << err_msg << endl;
			return g_exit_code_sock_error;
		}

		rv = sendto(send_sock, "",
				0, 0, servinfo->ai_addr, servinfo->ai_addrlen);

		if (rv < 0) {
			cerr << argv[0] << ": sendto error" << endl;
			return g_exit_code_sendto;
		}

		struct pollfd fds;
		fds.fd = send_sock;
		fds.events = 0;
		if ((rv = poll(&fds, 1, 2000)) < 0) {
			cerr << argv[0] << ": poll error" << endl;
			perror("poll");
			return g_exit_code_poll;
		}

		if (0 == rv) {
			cout << "timeout ***" << endl;
			++trace_opts.first_ttl;
			continue;
		}

		char buffer[MAXBUFLEN];
		struct iovec iov;      /* Data array */
		struct msghdr message; /* Message header */
		struct icmphdr icmph;  /* ICMP header */
		struct sockaddr_storage their_addr;

		iov.iov_base = &icmph;
		iov.iov_len = sizeof(icmph);
		message.msg_name = &their_addr;
		message.msg_namelen = sizeof(struct sockaddr_in);
		message.msg_iov = &iov;
		message.msg_iovlen = 1;
		message.msg_flags = 0;
		message.msg_control = buffer;
		message.msg_controllen = sizeof(buffer);

		rv = recvmsg(send_sock, &message, MSG_ERRQUEUE);
		if (rv < 0) {
			cerr << argv[0] << ": recvmsg error" << endl;
			return g_exit_code_recvmsg;
		}

		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
			cmsg;
			cmsg = CMSG_NXTHDR(&message, cmsg))
		{
			if (cmsg->cmsg_level == SOL_IP
				&& cmsg->cmsg_type == IP_RECVERR)
			{
				int code = get_icmp_code(cmsg, &their_addr);
				if (code < 0) {
					cout << "negative code" << endl;
					break;
				}
				switch (code) {
				case ICMP_HOST_UNREACH:
					cout << "H! ";
					break;
				case ICMP_NET_UNREACH:
					cout << "N! ";
					break;
				case ICMP_PROT_UNREACH:
					cout << "P! ";
					break;
				// case ? cout << "X! ";
				case ICMP_DEST_UNREACH:
					done = true;
					break;
				}
				break;
			}
		}

		cout << trace_opts.first_ttl << ": got packet from ";
		cout << get_addr_str_represent(&their_addr) << endl;

		close(send_sock);
		++trace_opts.first_ttl;
	}

	freeaddrinfo(servinfo);
	return 0;
}