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

/* Sizes in bytes */
#define ETHERNET_HDR_SIZE 14
#define IP_HDR_SIZE 20

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
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);



  /* fill in code here */

  struct sr_ethernet_hdr *ethernet_hdr = sr_extract_ethernet_hdr(packet);
  unsigned int ip_packet_len = len - ETHERNET_HDR_SIZE;
  uint8_t *ip_packet = sr_extract_ip_packet(ethernet_hdr, ip_packet_len);
  struct sr_ip_hdr *ip_hdr = sr_extract_ip_hdr(ip_packet);

  struct sr_icmp_hdr* icmp_header;

  // Check if we are recipient of the packet
  if (sr_is_packet_recipient(sr, ip_packet)) {
    sr_handle_packet_reply(sr, (sr_ip_hdr_t*) ip_packet);
  } else {
    // forward packet
    sr_handle_packet_forwarding(sr, ip_packet, ip_hdr);
  }
}/* end sr_handlepacket */

// Determine if the router contains the intended recipient of the ip packet
bool sr_is_packet_recipient(struct sr_instance *sr, uint8_t *ip_packet) {
  struct sr_if* if_walker = sr->if_list;

  while(if_walker)
  {
    if(if_walker->ip == ip_packet->ip_dst) { 
      return true; 
    }
    if_walker = if_walker->next;
  }

  return false;
}

void sr_handle_packet_reply(struct sr_instance* sr, struct sr_ip_hdr* ip_packet) {
  // Return a port unreachable for UDP or TCP type packets through a icmp_t3_header
  if (ip_packet->ip_p == sr_ip_protocol.ip_protocol_tcp || ip_packet->ip_p == sr_ip_protocol.ip_protocol_udp) {
    struct sr_icmp_t3_hdr* icmp_header = create_icmp_header(
      sr_icmp_type.icmp_type_dest_unreachable, 
      sr_icmp_code.icmp_code_2,
      0,
      (uint8_t *)null);

    //TODO: Do same as below except for icmp_t3_header

  } else if (ip_packet->ip_p == sr_ip_protocol.ip_protocol_icmp && 
    ck_sum(ip_packet, ip_packet->ip_len))) {
    // If the packet is a valid ICMP echo request, send an echo reply through a icmp_header
    struct sr_icmp_hdr* icmp_header = create_icmp_hdr(sr_icmp_type.icmp_type_echo_reply, sr_icmp_code.icmp_code_0);

    // TODO: create the appropriate ethernet/ip headers and then send. Clean up/refactor code
    // for creation/sending 
    if (icmp_header != null) {
      uint32_t temp_ether_shost = ethernet_hdr->ether_shost;

      ethernet_hdr->ether_shost = ethernet_hdr->ether_dhost;
      ethernet_hdr->dhost = sr_arpcache_lookup(sr->sr_arpcache, temp_ether_shost);

      uint32_t temp_ip_src = ip_packet->ip_src;

      ip_packet->ip_src = ip_packet->ip_dst;
      ip_packet->ip_dst = temp_ip_src;
      ip_packet->ip_ttl = INIT_TTL;
      ip_packet->ip_p = sr_ip_protocol.ip_protocol_icmp;

      // TODO: Insert append icmp packet to ip packet

      ip_packet->ip_len = 0; //TODO: Calculate new ip header length
      ip_packet->ip_sum = cksum(ip_packet, ip_packet->ip_len);

      // TODO: Append ip packet to ethernet packet and send;
    }
  }
}

struct sr_ethernet_hdr_t *sr_extract_ethernet_hdr(uint8_t *ethernet_packet) {
  struct sr_ethernet_hdr* ethernet_hdr  = malloc(sizeof(struct sr_ethernet_hdr));
  memcpy(sr_ethernet_hdr, ethernet_packet, ETHERNET_HDR_SIZE)
  return ethernet_hdr;
}

uint8_t *sr_extract_ip_packet(uint8_t *ethernet_packet, unsigned int ip_packet_len) {
  uint8_t *ip_packet = malloc(ip_packet_len);
  memcpy(ip_packet, ethernet_packet + ETHERNET_HDR_SIZE, ip_packet_len);
  return ip_packet;
}

// Get ip header from ip packet, returned sr_ip_hdr points to the same address as ip_packet
struct sr_ip_hdr *sr_extract_ip_hdr(uint8_t *ip_packet) {
  uint8_t *ip_hdr = ip_packet;
  return (struct sr_ip_hdr*) ip_hdr;
}

bool sr_handle_packet_forwarding(struct sr_instance *sr, uint8_t *ip_packet, struct sr_ip_hdr *ip_hdr, unsigned int ip_packet_len) {
  if (!sr_ip_packet_is_valid(ip_packet, ip_packet_len)) {
    return false;
  }

  ip_hdr->ip_ttl -= 1;

  if (id_hdr->ip_ttl <= 0) {
    // TODO: Send ICMP time exceeded
  } else {
    ip_hdr->ip_sum = cksum(ip_packet, ip_packet_len);

    // Gordon's code goes here
  }
}

// Check for packet minimum length and checksum
bool sr_ip_packet_is_valid(uint8_t *ip_packet, unsigned int ip_packet_len) {
  return ip_packet_len >= IP_HDR_SIZE && 
    verify_cksum(ip_packet, ip_packet_len, ip_packet->ip_sum);
}