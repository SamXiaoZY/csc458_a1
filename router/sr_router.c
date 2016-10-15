/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t *packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  // The ethernet packet
  assert(packet);
  // The incoming interface
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  struct sr_ethernet_hdr *ethernet_hdr = sr_copy_ethernet_hdr(packet);
  struct sr_if* self_interface = sr_get_interface(sr, interface);

  // If receive an ARP packet and we are recipient
  if (ethernet_hdr->ether_type == sr_ethertype.ethertype_arp && sr_is_packet_recipient(sr, arp_hdr->ar_tip)) {
    struct sr_arp_hdr *arp_hdr = sr_copy_arp_hdr(packet);

    // If ARP request, reply with our mac address
    if (arp_hdr->ar_op == sr_arp_opcode.arp_op_request) {
      sr_handle_arp_request(ethernet_hdr, arp_hdr, self_interface);

    } else if (arp_hdr->ar_op == sr_arp_opcode.arp_op_request) {
      // If ARP response, remove the ARP request from the queue, update cache, forward any packets that were waiting on that ARP request
      // Call Gorden's function
    }

    free(arp_hdr);

  } else if (ethernet_hdr->ether_type == sr_ethertype.ethertype_ip) {
    // If receive an IP packet
    unsigned int ip_packet_len = len - ETHERNET_HDR_SIZE;
    uint8_t *ip_packet = sr_copy_ip_packet(ethernet_hdr, ip_packet_len);

    // Check if the received packet is valid, if not drop the packet
    if (!sr_ip_packet_is_valid(ip_packet, ip_packet_len)) {
      free(ethernet_hdr);
      free(ip_packet);
      break;
    }

    // Check if we are recipient of the packet
    if (sr_is_packet_recipient(sr, ip_packet->ip_dst)) {
      sr_handle_packet_reply(sr, ip_packet, ethernet_hdr);

    } else {
      sr_handle_packet_forward(sr, ip_packet, ethernet_hdr, ip_packet_len);
    }

    free(ip_packet);
  }

  free(ethernet_hdr);
}/* end sr_handlepacket */


// Copy the header from the Ethernet packet
struct sr_ethernet_hdr_t *sr_copy_ethernet_hdr(uint8_t *ethernet_packet) {
  struct sr_ethernet_hdr* ethernet_hdr  = malloc(sizeof(struct sr_ethernet_hdr));
  memcpy(sr_ethernet_hdr, ethernet_packet, ETHERNET_HDR_SIZE);
  return ethernet_hdr;
}


// Copy the header from the ARP packet
struct sr_arp_hdr *sr_copy_arp_hdr(uint8_t *ethernet_packet) {
  struct sr_arp_hdr* arp_hdr  = malloc(sizeof(struct sr_arp_hdr));
  memcpy(arp_hdr, ethernet_packet, ARP_HDR_SIZE);
  return arp_hdr;
}


// Copy the IP packet from the Ethernet packet
uint8_t *sr_copy_ip_packet(uint8_t *ethernet_packet, unsigned int ip_packet_len) {
  uint8_t *ip_packet = malloc(ip_packet_len);
  memcpy(ip_packet, ethernet_packet + ETHERNET_HDR_SIZE, ip_packet_len);
  return ip_packet;
}


// Determine if the router contains the intended recipient of the ip packet
bool sr_is_packet_recipient(struct sr_instance *sr, uint32_t ip) {
  struct sr_if* if_walker = sr->if_list;

  while(if_walker)
  {
    if(if_walker->ip == ip) { 
      return true; 
    }
    if_walker = if_walker->next;
  }

  return false;
}


// Send back the MAC address of our incoming interface to the sender
void sr_handle_arp_request(struct sr_ethernet_hdr *ethernet_hdr, struct sr_arp_hdr *arp_hdr, struct sr_if* self_interface) {
  struct sr_arp_hdr *arp_reponse_hdr = sr_create_arp_response_hdr(arp_hdr, self_interface->addr, self_interface->ip);
  sr_create_send_ethernet_packet(ethernet_hdr->ether_shost, 
      ethernet_hdr->ether_dhost, 
      sr_ethertype.ethertype_arp, 
      (uint8_t *) arp_reponse_hdr, 
      sizeof(sr_arp_hdr));
}


// Set source ip, source MAC and target MAC of the ARP response header
struct sr_arp_hdr *sr_create_arp_response_hdr(struct sr_arp_hdr *arp_hdr, unsigned char *self_mac, uint32_t self_ip, unsigned char target_mac) {
  arp_hdr->ar_sha = self_mac;
  arp_hdr->ar_sip = self_ip;
  arp_hdr->ar_tha = target_mac;
  return arp_hdr;
}


// Create an Ethernet packet and send it
void sr_create_send_ethernet_packet(uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t ethertype, uint8_t *data, uint16_t len) {
  uint8_t *ethernet_packet = createEthernetHdr(ether_dhost, ether_shost, ethertype, ethertype, data, len);
  sr_send_packet(sr, ethernet_packet, len + sizeof(sr_ethernet_hdr), get_interface_from_mac(((sr_ethernet_hdr *) ethernet_packet)->ether_dhost, sr));
}


// Check for packet minimum length and checksum
bool sr_ip_packet_is_valid(uint8_t *ip_packet, unsigned int ip_packet_len) {
  return ip_packet_len >= IP_HDR_SIZE && cksum(ip_packet, ip_packet_len) == 0;
}


void sr_handle_packet_reply(struct sr_instance* sr, uint8_t *ip_packet, struct sr_ethernet_hdr* ethernet_hdr) {

  struct sr_ip_hdr* ip_hdr = (sr_ip_hdr*) ip_packet;
  // Return a port unreachable for UDP or TCP type packets through a icmp_t3_header
  if (ip_hdr->ip_p == sr_ip_protocol.ip_protocol_tcp || ip_hdr->ip_p == sr_ip_protocol.ip_protocol_udp) {
    struct sr_icmp_t3_hdr* icmp_hdr = create_icmp_header(
      sr_icmp_type.icmp_type_dest_unreachable, 
      sr_icmp_code.icmp_code_3,
      (uint8_t *)null,
      (uint8_t *)null, // next hub mtu?
      ip_packet);

    createAndSendIPPacket(sr, ip_packet, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, (uint8_t*) icmp_hdr, sizeof(sr_icmp_t3_hdr));
  } else if (ip_packet->ip_p == sr_ip_protocol.ip_protocol_icmp && ck_sum(ip_packet, ip_packet->ip_len))) {
    // If the packet is a valid ICMP echo request, send an echo reply through a icmp_header
    struct sr_icmp_hdr * icmp_hdr  = create_icmp_header(sr_icmp_type.icmp_type_echo_reply, sr_icmp_code.icmp_code_0);

    createAndSendIPPacket(sr, ip_packet, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, (uint8_t *)icmp_hdr, sizeof(sr_icmp_hdr));
  }
}


void sr_handle_packet_forward(struct sr_instance *sr, uint8_t *ip_packet, struct sr_ip_hdr *ip_hdr, unsigned int ip_packet_len, struct sr_ethernet_hdr *ethernet_hdr) {
  ip_hdr->ip_ttl -= 1;
  if (id_hdr->ip_ttl <= 0) {
    // Send ICMP time exceeded
    uint8_t* datagram = malloc(sizeof(uint8_t));
    memcpy(datagram, &ip_packet->buf[sizeof(sr_ip_hdr_t)], DATAGRAM_SIZE);

    struct sr_icmp_t3_hdr_t* icmp_t3_hdr = createICMPt3hdr(sr_icmp_type.icmp_time_exceeded, 
        sr_icmp_code.icmp_code_0,
        (uint8_t *)null,
        (uint8_t *)null,
        ip_hdr,
        datagram);
    createAndSendIPPacket(sr, ip_packet, (uint8_t*) icmp_hdr, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, icmp_t3_hdr, sizeof(sr_icmp_t3_hdr));

  } else {
    // Update IP packet checksum
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_packet, ip_packet_len);

    // Get the MAC address of next hub
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr->cache, ip_hdr->ip_dst);

    struct sr_rt* longestPrefixIPMatch = getInterfaceLongestMatch(sr->routing_table);

    // Send ICMP network unreachable if the ip cannot be identified through our routing table
    if (longestPrefixIPMatch == null) {
      uint8_t* datagram = malloc(sizeof(uint8_t));
      memcpy(datagram, &ip_packet->buf[sizeof(sr_ip_hdr_t)], DATAGRAM_SIZE);

      struct sr_icmp_t3_hdr* icmp_t3_hdr = createICMPt3hdr(sr_icmp_type.icmp_type_dest_unreachable, 
        sr_icmp_code.icmp_code_0,
        0,
        0,
        ip_hdr,
        datagram);

      createAndSendICMPPacket(sr, ethernet_hdr, ip_packet, (uint8_t *)icmp_t3_hdr, sizeof(icmp_t3_hdr));
    }
    else if (arp_entry != null) {
      // Cache hit for ip_dst, forward the packet
      createAndSendIPPacket(sr, ip_packet, ethernet_hdr->ether_dhost, arp_entry->mac, (uint8_t*) icmp_hdr, sizeof(sr_icmp_t3_hdr));
    } else {
      // Entry for ip_dst missing in cache table, queue the packet
      char* iface = get_interface_from_mac(ethernet_hdr->shost, sr);
      sr_arpcache_queuereq(sr->cache, ip_hdr->ip_dst, ip_packet, ip_packet_len, iface);
    }
    free(arp_entry);
  }
}

void createAndSendIPPacket(struct sr_instance* sr, struct sr_ip_hdr* ip_packet, uint8_t* ether_source, uint8_t* ether_dest, uint8_t* ip_payload, uint8_t size) {

  // Create ip packet by wrapping it over the payload
  struct sr_ip_hdr_t* ip_hdr = createIPHdr(ip_payload, 
      size, 
      ip_packet->ip_dst, 
      ip_packet->ip_src,
      sr_ip_protocol.ip_protocol_icmp);

  // Create ethernet packet by wrapping it over the ip packet
  uint8_t * eth_hdr = createEthernetHdr(sr_arpcache_lookup(sr->sr_arpcache, ether_source),
      ether_dest,
      sr_ethertype.ethertype_ip,
      (uint8_t *) ip_hdr,
      sizeof(struct eth_hdr*) + ip_hdr->ip_len);

  sr_send_packet(sr, eth_hdr, sizeof(eth_hdr), get_interface_from_mac(eth_hdr->ether_dhost, sr));

  //TODO: Free all memory and perform correct conversion of network <-> local endian type
}
