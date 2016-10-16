#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"

/* Sizes in bytes */
#define ETHERNET_HDR_SIZE 14
#define IP_HDR_SIZE 20
#define DATAGRAM_SIZE 8


// Creates the checksum of the first len bytes of _data
uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

int verify_cksum (const void *_data, int len, uint16_t cksum) {
  // Get the complement of the recomputed checksum to get the sum of all 16
  return ~cksum(_data, len) + cksum == 0;
}

uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}

struct sr_icmp_hdr *create_icmp_header(uint8_t type, uint8_t code) {
    struct sr_icmp_hdr* icmp_header = malloc(sizeof(struct sr_icmp_hdr));
    icmp_header->icmp_type = type;
    icmp_header->icmp_code = code;
    icmp_header->icmp_sum = htons(cksum((void*)sr_icmp_hdr, sizeof(struct sr_icmp_hdr)));
    return icmp_header;
}

struct sr_icmp_t3_hdr_t* createICMPt3hdr(uint8_t icmp_type, uint8_t icmp_code, uint16_t next_mtu, uint8_t* ip_packet) {
    struct sr_icmp_t3_hdr* icmp_t3_hdr = malloc(sizeof(sr_icmp_t3_hdr_t));
    icmp_t3_hdr->icmp_type = icmp_type;
    icmp_t3_hdr->icmp_code = icmp_code;
    icmp_t3_hdr->next_mtu = htons(next_mtu);

    memcpy(icmp_t3_hdr->data, ip_packet, ICMP_DATA_SIZE);
    icmp_t3_hdr->icmp_sum = htons(cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t) + ICMP_DATA_SIZE));
    
    return icmp_t3_hdr;
}

struct sr_ip_hdr_t* createIPHdr(uint8_t* data, uint8_t size, uint32_t IPSrc, uint32_t IPDest, uint8_t protocol) {
    sr_ip_hdr_t* output = malloc(sizeof(sr_ip_hdr_t) + size); 
    output->ip_tos = 0; // Best effort
    output->ip_len = size;
    output->ip_id = 0; // No ip fragments
    output->ip_off = 0; // No ip fragments(offset)
    output->ip_ttl = htons(INIT_TTL);
    output->ip_p = protocol;
    output->ip_src = htonl(ip_src);
    output->ip_dst = htonl(ip_dst);

    uint16_t checksum = cksum(output, sizeof(sr_ip_hdr_t));
    output->ip_sum = htonl(cksum);

    memcpy(&(uint8_t*)output[sizeof(sr_ip_hdr_t)], data, size);
    return output;
}

uint8_t *createEthernetHdr(uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t ethertype, uint8_t *data, uint16_t len){

    uint8_t* output = malloc(sizeof(sr_ethernet_hdr_t)+len);

    memcpy(output, ether_dhost, ETHER_ADDR_LEN);
    memcpy(output + ETHER_ADDR_LEN, ether_shost, ETHER_ADDR_LEN);
    memcpy(&output[ETHER_ADDR_LEN*2], &ethertype, sizeof(uint16_t));
    memcpy(&output[ETHER_ADDR_LEN*2+sizeof(uint16_t)], data, len);

    return output;
}
   
struct sr_rt* getInterfaceLongestMatch(struct sr_rt *routingTable, uint32_t targetIP) {

    struct sr_rt* currRTEntry = routingTable;
    uint32_t longestMask = 0;
    struct sr_rt* output = NULL;

    while(currRTEntry){

        if(targetIPMatchesEntry(ntohl((uint32_t)currRTEntry->dest.s_addr), (uint32_t)currRTEntry->mask.s_addr, targetIP)==1){
            if((uint32_t)currRTEntry->mask.s_addr > longestMask){
                longestMask = (uint8_t)currRTEntry->mask.s_addr;
                output = currRTEntry;
            }
        }
        currRTEntry = currRTEntry->next;
    }
    return output;
}

/*returns 1 for true, 0 for false, make sure inputs are in host order*/
int targetIPMatchesEntry(uint32_t entry, uint32_t mask, uint32_t target) {
    uint32_t testMask = 0xFFFFFFFF;
    testMask = testMask << (32 - mask);

    if((entry & testMask) == (target & testMask)){
        return 1;
    }
    return 0;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}