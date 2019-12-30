#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h> 
#include <errno.h>
#include <netinet/ip.h>

#define SEND 0
#define RECV 1


#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60


unsigned char buffer[BUF_SIZE];
struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
struct arp_hdr *arp_resp = (struct arp_hdr *) (buffer + ETH2_HEADER_LEN);



struct arp_hdr {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    uint16_t ar_op;
    unsigned char ar_sha[6];
    unsigned char ar_sip[4];
    unsigned char ar_tha[6];
    unsigned char ar_tip[4];
};


unsigned int get_netmask(char *if_name, int sockfd){
 struct ifreq if_idx;
 memset(&if_idx, 0, sizeof(struct ifreq));
 strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);

 if((ioctl(sockfd, SIOCGIFNETMASK, &if_idx)) == -1)
 perror("ioctl():");

 return ((struct sockaddr_in *)&if_idx.ifr_netmask)->sin_addr.s_addr;
}

unsigned int get_ip_saddr(char *if_name, int sockfd){
 struct ifreq if_idx;
 memset(&if_idx, 0, sizeof(struct ifreq));
 strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);

 if (ioctl(sockfd, SIOCGIFADDR, &if_idx) < 0)
 perror("SIOCGIFADDR");

 return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr;
}

int16_t ip_checksum(void* vdata,size_t length) {
 char* data=(char*)vdata;
 uint32_t acc=0xffff;

 for (size_t i=0;i+1<length;i+=2) 
 {
    uint16_t word;
    memcpy(&word,data+i,2);
    acc+=ntohs(word);
    if (acc>0xffff) 
    {
    acc-=0xffff;
    }
 }

 if (length&1) 
 {
    uint16_t word=0;
    memcpy(&word,data+length-1,1);
    acc+=ntohs(word);
    if (acc>0xffff) 
        {
        acc-=0xffff;
    }
 }
 return htons(~acc);
}

int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) 
    {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } 
    else 
    {
        printf("Not AF_INET\n");
        return 1;
    }
}


int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) 
    {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) 
            return -2;

        else 
        {
            strcpy(out, ip);
            return 0;
        }
    } 
    else 
        return -1;

}

int get_if_ip4(int fd, const char *ifname, uint32_t *ip) 
{ }

int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_hdr *arp_req = (struct arp_hdr *) (buffer + ETH2_HEADER_LEN);
    int index;
    ssize_t ret, length = 0;

    memset(send_req->h_dest, 0xff, MAC_LENGTH);
    memset(arp_req->ar_tha, 0x00, MAC_LENGTH);
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->ar_sha, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    send_req->h_proto = htons(ETH_P_ARP);

    arp_req->ar_hrd = htons(HW_TYPE);
    arp_req->ar_pro = htons(ETH_P_IP);
    arp_req->ar_hln = MAC_LENGTH;
    arp_req->ar_pln = IPV4_LENGTH;
    arp_req->ar_op = htons(ARP_REQUEST);

    memcpy(arp_req->ar_sip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->ar_tip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret < 0) 
    {
        perror("sendto():");
        goto out;
    }
    err = 0;
    out:
        return err;
}


int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) 
    {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) 
    {
        printf("Interface name too long, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    size_t if_name_len = strlen(ifname);
    memcpy(ifr.ifr_name, ifname, if_name_len);
    ifr.ifr_name[if_name_len] = 0;

    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) //assign socket to device //this is the error line
	{
            fprintf(stderr, "ioctl: errno %d / %s\n", errno, strerror(errno));
            goto out;
    }   
    *ifindex = ifr.ifr_ifindex;

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) 
    {
        perror("SIOCGIFINDEX");
        goto out;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) 
        goto out;

    err = 0;
    out:
        if (sd > 0) 
            close(sd);

    return err;
}

int bind_arp(int ifindex, int *fd)
{
    int ret = -1;

    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) 
    {
        perror("socket()");
        goto out;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) 
    {
        perror("bind");
        goto out;
    }

    ret = 0;
    out:
        if (ret && *fd > 0) 
            close(*fd);

    return ret;
}

int read_arp(int fd)
{
    int ret = -1;
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length < 0) 
    {
        perror("recvfrom()");
        goto out;
    }
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) 
    {
        printf("Not an ARP packet\n");
        goto out;
    }
    if (ntohs(arp_resp->ar_op) != ARP_REPLY) 
    {
        printf("Not an ARP reply\n");
        goto out;
    }

    printf("received ARP with len=%ld\n", length);
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->ar_sip, sizeof(uint32_t));

    printf("Sender IP: %s\n", inet_ntoa(sender_a));

    printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", arp_resp->ar_sha[0], arp_resp->ar_sha[1], arp_resp->ar_sha[2], arp_resp->ar_sha[3], arp_resp->ar_sha[4], arp_resp->ar_sha[5]);

    ret = 0;

    out:
        return ret;
}


void send(){

	int sockfd, tx_len = 0;
	struct ifreq if_idx;
	struct ifreq if_mac;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];


	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = 0x00;
	eh->ether_dhost[1] = 0x00;
	eh->ether_dhost[2] = 0x00;
	eh->ether_dhost[3] = 0x00;
	eh->ether_dhost[4] = 0x00;
	eh->ether_dhost[5] = 0x00;
	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);

	/* Packet data */
	sendbuf[tx_len++] = 0xde;
	sendbuf[tx_len++] = 0xad;
	sendbuf[tx_len++] = 0xbe;
	sendbuf[tx_len++] = 0xef;

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = 0x00;
	socket_address.sll_addr[1] = 0x00;
	socket_address.sll_addr[2] = 0x00;
	socket_address.sll_addr[3] = 0x00;
	socket_address.sll_addr[4] = 0x00;
	socket_address.sll_addr[5] = 0x00;

	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
	else
		printf("Send Suceeded.\n");
}

void recv(){

	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buf[1024];
	char ifName[IFNAMSIZ];

	struct ether_header *eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(0x0800))) == -1) {
		perror("listener: socket");	
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	repeat:	
		printf("listener: Waiting to recv from...\n");
		numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
		printf("listener: got packet %lu bytes\n", numbytes);

		/* Check the packet is for me */
		/*if (eh->ether_dhost[0] == 0x00 &&
				eh->ether_dhost[1] == 0x00 &&
				eh->ether_dhost[2] == 0x00 &&
				eh->ether_dhost[3] == 0x00 &&
				eh->ether_dhost[4] == 0x00 &&
				eh->ether_dhost[5] == 0x00) {
			printf("Correct destination MAC address\n");
		} else {
			printf("Wrong destination MAC: %x:%x:%x:%x:%x:%x\n",
							eh->ether_dhost[0],
							eh->ether_dhost[1],
							eh->ether_dhost[2],
							eh->ether_dhost[3],
							eh->ether_dhost[4],
							eh->ether_dhost[5]);
			ret = -1;
			goto done;
		}*/

		/* Get source IP */
		((struct sockaddr_in *)&their_addr)->sin_addr.s_addr = iph->saddr;
		inet_ntop(AF_INET, &((struct sockaddr_in*)&their_addr)->sin_addr, sender, sizeof sender);

		/* Look up my device IP addr if possible */
		strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(sockfd, SIOCGIFADDR, &if_ip) >= 0) { /* if we can't check then don't */
			printf("Source IP: %s\n My IP: %s\n", sender, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
			/* ignore if I sent it */
			if (strcmp(sender, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)) == 0)	{
				printf("but I sent it :(\n");
				ret = -1;
				goto done;
			}
		}

		/* UDP payload length */
		ret = ntohs(udph->len) - sizeof(struct udphdr);

		/* Print packet */
		printf("\tData:");
		for (i=0; i<numbytes; i++) printf("%02x:", buf[i]);
		printf("\n");

		goto repeat;

	done:
		close(sockfd);

}


int send_message(char *ifname, char *dest_ip, char *router_ip, char *message)
{
    int type = check_IP(source_ip, dest_ip);
    

    if(type == 1)//on the same local network
    {
        uint32_t dst = inet_addr(dest_ip);
        int src;
        int ifindex;
        char mac[MAC_LENGTH];

        if (get_if_info(ifname, &src, mac, &ifindex)) 
        {
            printf("get_if_info failed, interface %s not found or no IP set?\n", ifname);
            goto out;
        }
        int arp_fd;
        if (bind_arp(ifindex, &arp_fd)) 
        {
            printf("Failed to bind_arp()\n");
            goto out;
        }

        if (send_arp(arp_fd, ifindex, mac, src, dst)) 
        {
            printf("Failed to send_arp\n");
            goto out;
        }

        while(1) //wait for reply
        {
            int r = read_arp(arp_fd);
            if (r == 0) 
                break;
        }

        out:
            if (arp_fd) 
            {
                close(arp_fd);
                arp_fd = 0;
            }

            //at this point we have the dest MAC address
            
    }

    else if(type == 2)//not on same local network, need to send through router
    {
        uint32_t dst = inet_addr(router_ip);
        int src;
        int ifindex;
        char mac[MAC_LENGTH];

        if (get_if_info(ifname, &src, mac, &ifindex)) 
        {
            printf("get_if_info failed, interface %s not found or no IP set?\n", ifname);
            goto out;
        }
        int arp_fd;
        if (bind_arp(ifindex, &arp_fd)) 
        {
            printf("Failed to bind_arp()\n");
            goto out;
        }

        if (send_arp(arp_fd, ifindex, mac, src, dst)) 
        {
            printf("Failed to send_arp\n");
            goto out;
        }

        while(1) //wait for reply
        {
            int r = read_arp(arp_fd);
            if (r == 0) 
                break;
        }

        out:
            if (arp_fd) 
            {
                close(arp_fd);
                arp_fd = 0;
            }

    }



    return 0;
}

int recv_message(char *ifname)
{
    recv();
    return 0;
}

int check_IP(char *source_ip, char *dest_ip)
{

}

int main(int argc, const char **argv)
{
	int correct=0;
    const char *ifname;
    const char *dest_ip;
    const char *router_ip;
    char message[60];
	memset(message, 0, 60);

	if (argc > 1){

        
		if(strncmp(argv[1],"Send", 4)==0)
        {
			if (argc == 5)
            {
				mode=SEND; 
				correct=1;
                dest_ip = argv[3];
                router_ip = argv[4];
                strncpy(message, argv[4], 60);
            }
		}
		else if(strncmp(argv[1],"Recv", 4)==0)
        {
			if (argc == 3)
            {
				mode=RECV;
				correct=1;
			}
		}
		ifname = argv[2];
	 }
	 if(!correct){
		fprintf(stderr, "./455_proj3 Send <InterfaceName>  <DestIP> <RouterIP> <Message>\n");
		fprintf(stderr, "./455_proj3 Recv <InterfaceName>\n");
		exit(1);
	 }

	if(mode == SEND){
		send_message(ifname, dest_ip, router_ip, message);
	}
	else if (mode == RECV){
		recv_message(ifname);
	}

	return 0;
}


