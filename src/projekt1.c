#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <getopt.h>
#include <errno.h>            // errno, perror()
#include "biblio.h"
#include <dlfcn.h>


int main(int argc, char **argv) {

	void *libr;
	uint16_t (*checksum)(uint16_t *addr, int len);
	uint16_t (*udp4_checksum)(struct ip iphdr, struct udphdr udphdr, uint8_t *payload,int payloadlen);

	// napisany przez nas program musi się komunikować z innym programem,który działa na komputerze o innym porządku bajtów.
	//Często najprościej jest przesyłać liczby jako tekst, gdyż jest on niezależny od innych czynników, jednak taki format
	//zajmuje więcej miejsca, a nie zawsze możemy sobie pozwolić na taką rozrzutność.
	//	Przykładem może być komunikacja sieciowa, w której przyjęło się, że dane przesyłane są w porządku big-endian.

	libr = dlopen("./proj.so", RTLD_LAZY); //ładowanie biblioteki z pliku

	checksum = dlsym(libr, "checksum");  // dlsym  pobiera "uchwyt" biblioteki dynamicznej
	udp4_checksum = dlsym(libr, "udp4_checksum");

	int status, frame_length, sd, bytes, *ip_flags;
	char *interface, *target, *src_ip, *dst_ip;
	struct ip iphdr;
	struct udphdr udphdr;
	uint8_t *data, *src_mac, *dst_mac, *ether_frame;
	struct addrinfo hints, *res;
	struct sockaddr_in *ipv4;
	struct sockaddr_ll device;
	struct ifreq ifr;
	void *tmp;

	// Allocate memory for various arrays.
	src_mac = allocate_ustrmem(6);
	dst_mac = allocate_ustrmem(6);
	data = allocate_ustrmem(IP_MAXPACKET);
	ether_frame = allocate_ustrmem(IP_MAXPACKET);
	interface = allocate_strmem(40);
	target = allocate_strmem(40);
	src_ip = allocate_strmem(INET_ADDRSTRLEN);
	dst_ip = allocate_strmem(INET_ADDRSTRLEN);
	ip_flags = allocate_intmem(4);

	char *dest = "127.0.0.1";
	char *sour = "10.0.0.1";
	int portzrd = 0;
	int portdoc = 0;
	int datalen = 8;
	int c;
	char *dane = "test";
	while ((c = getopt(argc, argv, "hdstpwc")) != -1) {

		switch (c) {
		case 'h':
			printf("\n");
			printf(" -s adres źródłowy\n");
			printf(" -d adres docelowy\n");
			printf(" -p port źródłowy \n");
			printf(" -t port docelowy \n");
			printf(" -w długość pakietu\n");
			printf(" -c dane\n");
			printf("\n");
			return 0;
		case 'd':
			dest = argv[optind];
			break;
		case 's':
			sour = argv[optind];
			break;
		case 't':
			portzrd = atoi(argv[optind]); //Funkcja jako argument pobiera liczbę w postaci ciągu znaków ASCII, a następnie zwraca jej wartość w formacie int.
			break;
		case 'p':
			portdoc = atoi(argv[optind]);
			break;
		case 'w':
			datalen = atoi(argv[optind]);
			break;
		case 'c':
			dane = argv[optind];
			break;
		default:
			printf("Błąd.\n");
			return 0;
		}

	}
	//Funkcja kopiuje tekst z tablicy 2 do tablicy 1. Funkcja kopiuje znak po znaku od początku, aż do końca tablicy lub znaku '\0', który też kopiuje.
	strcpy(interface, "wlp4s0"); // Interface to send packet through.
	strcpy(src_ip, sour); // Source IPv4 address: you need to fill this out
	strcpy(target, dest); // Destination URL or IPv4 address: you need to fill this out
	strcpy(data, dane); 	// UDP data


	//Funkcja htonl() przeksztalca wartosc long   integer  hostlong  z lokalnego  na sieciowy porzadek bajtow.
    //Funkcja htons() przeksztalca wartosc short  integer  hostshort z lokalnego  na sieciowy porz�dek bajt�w.
	//Funkcja ntohl() przeksztalca wartosc long   integer  netlong   z sieciowego na lokalny porz�dek bajt�w.
	//Funkcja ntohs() przeksztalca wartosc short  integer  netshort  z sieciowego na lokalny porz�dek bajt�w.

	// Submit request for a socket descriptor to look up interface.
	 sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
	// Use ioctl() to look up interface name and get its MAC address.
	memset(&ifr, 0, sizeof(ifr));  //Wypełnia kolejne bajty w pamięci ustaloną wartością.
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface); //zapisują test w podanej jako argument tablicy znaków.

	ioctl(sd, SIOCGIFHWADDR, &ifr); //funkcja ioctl, za pomocą której można wywołać funkcje na otwartym pliku urządzenia
	close(sd);						//Chodzi bardziej o wywołanie wcześniej zdefiniowanej w sterowniku operacji, dla której można też przekazać parametr.

	// Copy source MAC address.
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t)); //Funkcja kopiuje size bajtów z obiektu source do obiektu dest.

	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset(&device, 0, sizeof(device));
	device.sll_ifindex = if_nametoindex(interface);

	// Set destination MAC address: you need to fill these out
	dst_mac[0] = 0xff;
	dst_mac[1] = 0xff;
	dst_mac[2] = 0xff;
	dst_mac[3] = 0xff;
	dst_mac[4] = 0xff;
	dst_mac[5] = 0xff;

	// Fill out hints for getaddrinfo().
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	status = getaddrinfo(target, NULL, &hints, &res); //t�umaczenie adres�w i us�ug sieciowych
	ipv4 = (struct sockaddr_in *) res->ai_addr;
	tmp = &(ipv4->sin_addr);
	if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
		status = errno;
		fprintf(stderr, "inet_ntop() failed.\nError message: %s",strerror(status));
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);

	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
	device.sll_halen = 6;

	// IPv4 header
	iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t); // IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_v = 4; // Internet Protocol version (4 bits): IPv4
	iphdr.ip_tos = 0; // Type of service (8 bits)
	iphdr.ip_len = htons(IP4_HDRLEN + UDP_HDRLEN + datalen); // Total length of datagram (16 bits): IP header + UDP header + datalen
	iphdr.ip_id = htons(0); // ID sequence number (16 bits): unused, since single datagram

	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
	ip_flags[0] = 0; // Zero (1 bit)
	ip_flags[1] = 0; // Do not fragment flag (1 bit)
	ip_flags[2] = 0; // More fragments following flag (1 bit)
	ip_flags[3] = 0; // Fragmentation offset (13 bits)

	iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13)+ ip_flags[3]);
	iphdr.ip_ttl = 255;	// Time-to-Live (8 bits): default to maximum value
	iphdr.ip_p = IPPROTO_UDP;	// Transport layer protocol (8 bits): 17 for UDP


	status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src)); 	// Source IPv4 address (32 bits)      convert IPv4 and IPv6 addresses from text to binary form
	status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst)); 	// Destination IPv4 address (32 bits) convert IPv4 and IPv6 addresses from text to binary form

	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	//iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

	// UDP header
	udphdr.source = htons(portdoc); 			// Source port number (16 bits): pick a number
	udphdr.dest = htons(portzrd);				// Destination port number (16 bits): pick a number
	udphdr.len = htons(UDP_HDRLEN + datalen);	// Length of UDP datagram (16 bits): UDP header + UDP data
	udphdr.check = udp4_checksum(iphdr, udphdr, data, datalen); 	// UDP checksum (16 bits)

	// Fill out ethernet frame header.

	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header + UDP data)
	frame_length = 6 + 6 + 2 + IP4_HDRLEN + UDP_HDRLEN + datalen;

	// Destination and Source MAC addresses
	memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
	memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

	// Next is ethernet type code (ETH_P_IP for IPv4).
	// http://www.iana.org/assignments/ethernet-numbers
	ether_frame[12] = ETH_P_IP / 256;
	ether_frame[13] = ETH_P_IP % 256;

	// Next is ethernet frame data (IPv4 header + UDP header + UDP data).
	memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof(uint8_t));							// IPv4 header
	memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN, &udphdr,UDP_HDRLEN * sizeof(uint8_t)); 			// UDP header
	memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof(uint8_t));	// UDP data

	// Submit request for a raw socket descriptor.
	sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	// Send ethernet frame to socket.
	bytes = sendto(sd, ether_frame, frame_length, 0,(struct sockaddr *) &device, sizeof(device)); //wysyła dane z buffera przez socket na adres docelowy

	// Close socket descriptor.
	close(sd);

	// Free allocated memory.
	free(src_mac);
	free(dst_mac);
	free(data);
	free(ether_frame);
	free(interface);
	free(target);
	free(src_ip);
	free(dst_ip);
	free(ip_flags);

	return (EXIT_SUCCESS);
}

// Allocate memory for an array of chars.
char *
allocate_strmem(int len) {
	void *tmp;

	if (len <= 0) {
		fprintf(stderr,
				"ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n",
				len);
		exit(EXIT_FAILURE);
	}

	tmp = (char *) malloc(len * sizeof(char));
	if (tmp != NULL) {
		memset(tmp, 0, len * sizeof(char));
		return (tmp);
	} else {
		fprintf(stderr,
				"ERROR: Cannot allocate memory for array allocate_strmem().\n");
		exit(EXIT_FAILURE);
	}
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem(int len) {
	void *tmp;

	if (len <= 0) {
		fprintf(stderr,
				"ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n",
				len);
		exit(EXIT_FAILURE);
	}

	tmp = (uint8_t *) malloc(len * sizeof(uint8_t));
	if (tmp != NULL) {
		memset(tmp, 0, len * sizeof(uint8_t));
		return (tmp);
	} else {
		fprintf(stderr,
				"ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit(EXIT_FAILURE);
	}
}

// Allocate memory for an array of ints.
int *
allocate_intmem(int len) {
	void *tmp;

	if (len <= 0) {
		fprintf(stderr,"ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n",len);
		exit(EXIT_FAILURE);
	}

	tmp = (int *) malloc(len * sizeof(int));
	if (tmp != NULL) {
		memset(tmp, 0, len * sizeof(int));
		return (tmp);
	} else {
		fprintf(stderr,
				"ERROR: Cannot allocate memory for array allocate_intmem().\n");
		exit(EXIT_FAILURE);
	}
}



