#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"
#include "sr_if.h"

/* Creates the checksum of the first len bytes of _data*/
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

uint16_t get_network_cksum_from_hardware_ip(uint8_t* ip_hdr, int len) {
  transform_hardware_to_network_ip_header((sr_ip_hdr_t *) ip_hdr);
  uint16_t checksum = cksum(ip_hdr, len);
  transform_network_to_hardware_ip_header((sr_ip_hdr_t *) ip_hdr);

  return checksum;
}

uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}

sr_object_t create_icmp_packet(uint8_t type, uint8_t code, uint8_t* data, unsigned int len) {
  unsigned int icmp_hdr_size = sizeof(sr_icmp_hdr_t);
  struct sr_icmp_hdr* icmp_header = malloc(icmp_hdr_size);
  icmp_header->icmp_type = type;
  icmp_header->icmp_code = code;
  icmp_header->icmp_sum = 0;

  icmp_header->icmp_sum = cksum((void*)icmp_header, icmp_hdr_size);

  return create_combined_packet((uint8_t*)icmp_header, icmp_hdr_size, data, len);
}

sr_object_t create_icmp_t3_packet(uint8_t icmp_type, uint8_t icmp_code, uint16_t next_mtu, uint8_t* ip_packet) {
  /* Create ICMP type 3 header */
  unsigned int icmp_t3_hdr_size = sizeof(sr_icmp_t3_hdr_t);
  struct sr_icmp_t3_hdr* icmp_t3_hdr = malloc(icmp_t3_hdr_size);
  icmp_t3_hdr->icmp_type = icmp_type;
  icmp_t3_hdr->icmp_code = icmp_code;
  icmp_t3_hdr->next_mtu = next_mtu;
  icmp_t3_hdr->icmp_sum = 0;
  icmp_t3_hdr->unused = 0;

  transform_hardware_to_network_icmp_t3_header(icmp_t3_hdr);

  /* Copy over ip header and 8bytes of datagram as per ICMP type 3/11 definition */
  transform_hardware_to_network_ip_header((sr_ip_hdr_t *) ip_packet);
  memcpy(icmp_t3_hdr->data, ip_packet, ICMP_DATA_SIZE);
  icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, icmp_t3_hdr_size);
  transform_network_to_hardware_ip_header((sr_ip_hdr_t *) ip_packet);

  return create_packet((uint8_t *)icmp_t3_hdr, icmp_t3_hdr_size);
}


sr_object_t create_ip_packet(uint8_t protocol, uint32_t ip_src, uint32_t ip_dst, uint8_t* data, unsigned int len) {

  unsigned int ip_hdr_size = sizeof(sr_ip_hdr_t);
  sr_ip_hdr_t* output = malloc(ip_hdr_size); 
  output->ip_v = 4;
  output->ip_hl = 5;
  output->ip_tos = 0; /* Best effort*/
  output->ip_len = ip_hdr_size + len; /* Total length of header and data */
  output->ip_id = 0; /* No ip fragments */
  output->ip_off = IP_DF; /* No ip fragments(offset) */
  output->ip_ttl = INIT_TTL;
  output->ip_p = protocol;
  output->ip_src = ip_src; 
  output->ip_dst = ip_dst;
  output->ip_sum = 0;

  transform_hardware_to_network_ip_header(output);

  uint16_t checksum = cksum(output, ip_hdr_size);
  output->ip_sum = checksum;
  
  return create_combined_packet((uint8_t *) output, ip_hdr_size, data, len);
}

sr_object_t create_ethernet_packet(uint8_t* ether_shost, uint8_t* ether_dhost, uint16_t ethertype, uint8_t *data, unsigned int len) {
  unsigned int ethernet_hdr_size = sizeof(sr_ethernet_hdr_t);
  sr_ethernet_hdr_t* output = malloc(ethernet_hdr_size);

  memcpy(output->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
  memcpy(output->ether_shost, ether_shost, ETHER_ADDR_LEN);
  output->ether_type = ethertype;

  transform_network_to_hardware_ethernet_header(output);

  return create_combined_packet((uint8_t *) output, ethernet_hdr_size, data, len);
}

sr_object_t create_packet(uint8_t *packet, unsigned int len) {
  sr_object_t output;
  output.packet = packet;
  output.len = len;
  return output;
}

sr_object_t create_combined_packet(uint8_t *hdr, unsigned int hdr_len, uint8_t *data, unsigned int data_len) {
  sr_object_t output;
  uint8_t *combinedPacket = malloc(hdr_len + data_len);
  output.packet = combinedPacket;
  output.len = hdr_len + data_len;

  memcpy(combinedPacket, hdr, hdr_len);
  memcpy(combinedPacket + hdr_len, data, data_len);
  return output;
}
   
struct sr_rt* getInterfaceLongestMatch(struct sr_rt *routingTable, uint32_t targetIP) {
  /* Target IP should be hardware */
    struct sr_rt* currRTEntry = routingTable;
    uint32_t longestMask = 0;
    struct sr_rt* output = NULL;

    while(currRTEntry) {
        if(targetIPMatchesEntry(currRTEntry->dest.s_addr, currRTEntry->mask.s_addr, htonl(targetIP)) == 1){
            if((uint32_t)currRTEntry->mask.s_addr > longestMask) {
                longestMask = (uint8_t)currRTEntry->mask.s_addr;
                output = currRTEntry;
            }
        }
        currRTEntry = currRTEntry->next;
    }
    return output;
}

/*returns 1 for true, 0 for false, make sure inputs are in host order*/
/*check what the mask actually is*/
int targetIPMatchesEntry(uint32_t entry, uint32_t mask, uint32_t target) {
    /* uint32_t testMask = 0xFFFFFFFF; */
    /*testMask = testMask << (32 - mask);*/

    if((entry & mask) == (target & mask)) {
        return 1;
    }
    return 0;
}

void transform_network_to_hardware_ethernet_header(sr_ethernet_hdr_t* eth_hdr) {
  swap_mac(eth_hdr->ether_dhost);
  swap_mac(eth_hdr->ether_shost);
  eth_hdr->ether_type = ntohs(eth_hdr->ether_type);
}

void transform_network_to_hardware_ip_header(sr_ip_hdr_t* ip_hdr) {
  ip_hdr->ip_len = ntohs(ip_hdr->ip_len);
  ip_hdr->ip_id = ntohs(ip_hdr->ip_id);
  ip_hdr->ip_off = ntohs(ip_hdr->ip_off);
  
  ip_hdr->ip_src = ntohl(ip_hdr->ip_src);
  ip_hdr->ip_dst = ntohl(ip_hdr->ip_dst);
}

void transform_network_to_hardware_icmp_header(sr_icmp_hdr_t* icmp_hdr) {
  icmp_hdr->icmp_sum = ntohs(icmp_hdr->icmp_sum);
}

void transform_network_to_hardware_icmp_t3_header(sr_icmp_t3_hdr_t* icmp_t3_hdr) {
  icmp_t3_hdr->icmp_sum = ntohs(icmp_t3_hdr->icmp_sum);
  icmp_t3_hdr->unused = ntohs(icmp_t3_hdr->unused);
  icmp_t3_hdr->next_mtu = ntohs(icmp_t3_hdr->next_mtu);
}

void transform_network_to_hardware_arp_header(sr_arp_hdr_t* arp_hdr) {
  arp_hdr->ar_hrd = ntohs(arp_hdr->ar_hrd);
  arp_hdr->ar_pro = ntohs(arp_hdr->ar_pro);
  arp_hdr->ar_op = ntohs(arp_hdr->ar_op);
  arp_hdr->ar_sip = ntohl(arp_hdr->ar_sip);
  arp_hdr->ar_tip = ntohl(arp_hdr->ar_tip);
  swap_mac(arp_hdr->ar_sha);
  swap_mac(arp_hdr->ar_tha);
}

void transform_network_to_hardware_sr_if(struct sr_if* interface) {
  interface->ip = ntohl(interface->ip);
  interface->speed = ntohl(interface->speed);
  swap_mac(interface->addr);
}

void transform_hardware_to_network_ethernet_header(sr_ethernet_hdr_t* eth_hdr) {
  swap_mac(eth_hdr->ether_dhost);
  swap_mac(eth_hdr->ether_shost);
  eth_hdr->ether_type = htons(eth_hdr->ether_type);
}
void transform_hardware_to_network_ip_header(sr_ip_hdr_t* ip_hdr) {
  ip_hdr->ip_len = htons(ip_hdr->ip_len);
  ip_hdr->ip_id = htons(ip_hdr->ip_id);
  ip_hdr->ip_off = htons(ip_hdr->ip_off);
  ip_hdr->ip_src = htonl(ip_hdr->ip_src);
  ip_hdr->ip_dst = htonl(ip_hdr->ip_dst);
}

void transform_hardware_to_network_icmp_t3_header(sr_icmp_t3_hdr_t* icmp_t3_hdr) {
  icmp_t3_hdr->unused = htons(icmp_t3_hdr->unused);
  icmp_t3_hdr->next_mtu = htons(icmp_t3_hdr->next_mtu);
}

void transform_hardware_to_network_arp_header(sr_arp_hdr_t* arp_hdr) {
  arp_hdr->ar_hrd = htons(arp_hdr->ar_hrd);
  arp_hdr->ar_pro = htons(arp_hdr->ar_pro);
  arp_hdr->ar_op = htons(arp_hdr->ar_op);
  arp_hdr->ar_sip = htonl(arp_hdr->ar_sip);
  arp_hdr->ar_tip = htonl(arp_hdr->ar_tip);
  swap_mac(arp_hdr->ar_sha);
  swap_mac(arp_hdr->ar_tha);
}

void swap_mac(uint8_t *mac) {
  uint8_t temp = mac[0];
  mac[0] = mac[5];
  mac[5] = temp;

  temp = mac[1];
  mac[1] = mac[4];
  mac[4] = temp;

  temp = mac[2];
  mac[2] = mac[3];
  mac[3] = temp;
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
