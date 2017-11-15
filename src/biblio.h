/*
 * biblio.h
 *
 *  Created on: 15 lis 2017
 *      Author: musialke
 */

#ifndef BIBLIO_H_
#define BIBLIO_H_


// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define UDP_HDRLEN  8  // UDP header length, excludes data

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t udp4_checksum(struct ip, struct udphdr, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

#endif /* BIBLIO_H_ */
