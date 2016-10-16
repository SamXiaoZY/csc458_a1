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
  /* The ethernet packet*/
  assert(packet);
  /* The incoming interface*/
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  struct sr_ethernet_hdr *ethernet_hdr = sr_copy_ethernet_hdr(packet);
  struct sr_if* self_interface = sr_get_interface(sr, interface);
  struct sr_arp_hdr *arp_hdr = sr_copy_arp_hdr(packet);

  /* If receive an ARP packet and we are recipient*/
  if (ethernet_hdr->ether_type == ethertype_arp && sr_is_packet_recipient(sr, arp_hdr->ar_tip)) {

    /* If ARP request, reply with our mac address*/
    if (arp_hdr->ar_op == arp_op_request) {
      sr_handle_arp_request(sr, ethernet_hdr, arp_hdr, self_interface);

    } else if (arp_hdr->ar_op == arp_op_request) {
      /* If ARP response, remove the ARP request from the queue, update cache, forward any packets that were waiting on that ARP request
      all Gorden's function*/
    }

    free(arp_hdr);

  } else if (ethernet_hdr->ether_type == ethertype_ip) {
    /* If receive an IP packet*/
    unsigned int ip_packet_len = len - ETHERNET_HDR_SIZE;
    uint8_t *ip_packet = sr_copy_ip_packet((uint8_t* )ethernet_hdr, ip_packet_len);

    /* Check if the received packet is valid, if not drop the packet*/
    if (sr_ip_packet_is_valid(ip_packet, ip_packet_len)) {
        if (sr_is_packet_recipient(sr, ((sr_ip_hdr_t*)ip_packet)->ip_dst)) {
          sr_handle_packet_reply(sr, ip_packet, ethernet_hdr);
        } 
        else {
          /*TODO*/
          /*sr_handle_packet_forward(sr, (sr_ip_hdr_t*)ip_packet, ethernet_hdr, ip_packet_len);*/
        }
    }
    /* Check if we are recipient of the packet*/
    free(ip_packet);
  }
  free(ethernet_hdr);
}/* end sr_handlepacket */


/* Copy the header from the Ethernet packet*/
sr_ethernet_hdr_t *sr_copy_ethernet_hdr(uint8_t *ethernet_packet) {
  struct sr_ethernet_hdr* ethernet_hdr  = malloc(sizeof(struct sr_ethernet_hdr));
  memcpy(ethernet_hdr, ethernet_packet, ETHERNET_HDR_SIZE);
  return ethernet_hdr;
}

/* Copy the header from the ARP packet*/
struct sr_arp_hdr *sr_copy_arp_hdr(uint8_t *ethernet_packet) {
  struct sr_arp_hdr* arp_hdr  = malloc(sizeof(struct sr_arp_hdr));
  memcpy(arp_hdr, ethernet_packet+ETHERNET_HDR_SIZE, sizeof(sr_arp_hdr_t));
  return arp_hdr;
}

/* Copy the IP packet from the Ethernet packet*/
uint8_t *sr_copy_ip_packet(uint8_t *ethernet_packet, unsigned int ip_packet_len) {
  uint8_t *ip_packet = malloc(ip_packet_len);
  memcpy(ip_packet, ethernet_packet + ETHERNET_HDR_SIZE, ip_packet_len);
  return ip_packet;
}

/* Determine if the router contains the intended recipient of the ip packet*/
int sr_is_packet_recipient(struct sr_instance *sr, uint32_t ip) {
  struct sr_if* if_walker = sr->if_list;
  while(if_walker)
  {
    if(if_walker->ip == ip) { 
      return 1; 
    }
    if_walker = if_walker->next;
  }
  return 0;
}

/* Send back the MAC address of our incoming interface to the sender*/
void sr_handle_arp_request(struct sr_instance* sr, struct sr_ethernet_hdr *ethernet_hdr, struct sr_arp_hdr *arp_hdr, struct sr_if* self_interface) {
  /*TODO*/
  struct sr_arp_hdr *arp_reponse_hdr; /*= sr_create_arp_response_hdr(arp_hdr, self_interface->addr, self_interface->ip,);*/
  sr_create_send_ethernet_packet(sr,
      ethernet_hdr->ether_shost, 
      ethernet_hdr->ether_dhost, 
      ethertype_arp, 
      (uint8_t *) arp_reponse_hdr, 
      sizeof(sr_arp_hdr_t));
}

/* Set source ip, source MAC and target MAC of the ARP response header*/
struct sr_arp_hdr *sr_create_arp_response_hdr(struct sr_arp_hdr *arp_hdr, unsigned char *self_mac, uint32_t self_ip, unsigned char* target_mac, uint32_t target_ip) {
  memcpy(arp_hdr->ar_sha, self_mac, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = self_ip;
  memcpy(arp_hdr->ar_tha, target_mac, ETHER_ADDR_LEN);
  return arp_hdr;
}

/* Create an Ethernet packet and send it*/
void sr_create_send_ethernet_packet(struct sr_instance* sr, uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t ethertype, uint8_t *data, uint16_t len) {
  uint8_t *ethernet_packet = createEthernetHdr(ether_dhost, ether_shost, ethertype, data, len);
  sr_send_packet(sr, ethernet_packet, 
                len + sizeof(sr_ethernet_hdr_t), 
                get_interface_from_mac(((sr_ethernet_hdr_t *) ethernet_packet)->ether_dhost, sr));
}

/*  Check for packet minimum length and checksum*/
int sr_ip_packet_is_valid(uint8_t *ip_packet, unsigned int ip_packet_len) {
  return ip_packet_len >= IP_HDR_SIZE && cksum(ip_packet, ip_packet_len) == 0;
}

void sr_handle_packet_reply(struct sr_instance* sr, uint8_t *ip_packet, struct sr_ethernet_hdr* ethernet_hdr) {

  struct sr_ip_hdr* ip_hdr = (sr_ip_hdr_t*) ip_packet;
  /* Return a port unreachable for UDP or TCP type packets through a icmp_t3_header*/
  if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
    struct sr_icmp_t3_hdr* icmp_hdr; 

      /*= createICMPt3hdr(
      icmp_type_dest_unreachable, 
      icmp_code_3,
      0,
      0,
      ip_packet);*/

    createAndSendIPPacket(sr, (sr_ip_hdr_t*)ip_packet, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, (uint8_t*) icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  } else if (ip_hdr->ip_p == ip_protocol_icmp && cksum(ip_hdr, ip_hdr->ip_len)) {
    /* If the packet is a valid ICMP echo request, send an echo reply through a icmp_header*/
    struct sr_icmp_hdr * icmp_hdr  = create_icmp_header(icmp_type_echo_reply, icmp_code_0);

    createAndSendIPPacket(sr, (sr_ip_hdr_t*)ip_packet, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, (uint8_t *)icmp_hdr, sizeof(sr_icmp_hdr_t));
  }
}

void sr_handle_packet_forward(struct sr_instance *sr, uint8_t *ip_packet, struct sr_ip_hdr *ip_hdr, unsigned int ip_packet_len, struct sr_ethernet_hdr *ethernet_hdr) {
  ip_hdr->ip_ttl -= 1;
  if (ip_hdr->ip_ttl <= 0) {
    /* Send ICMP time exceeded*/
    uint8_t* datagram = malloc(sizeof(uint8_t));
    memcpy(datagram, ip_packet+sizeof(sr_ip_hdr_t), DATAGRAM_SIZE);

    sr_icmp_t3_hdr_t* icmp_t3_hdr = createICMPt3hdr(icmp_time_exceeded, 
        icmp_code_0,
        0,
        0,
        (uint8_t*)ip_hdr,
        IP_HDR_SIZE,
        datagram);
    createAndSendIPPacket(sr, (sr_ip_hdr_t*)ip_packet, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, (uint8_t*)icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

  } else {
    /* Update IP packet checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_packet, ip_packet_len);

    /* Get the MAC address of next hub*/

    struct sr_rt* longestPrefixIPMatch = getInterfaceLongestMatch(sr->routing_table,ip_hdr->ip_dst);
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);

    /* Send ICMP network unreachable if the ip cannot be identified through our routing table */
    if (longestPrefixIPMatch == NULL) {
      uint8_t* datagram = malloc(sizeof(uint8_t));
      memcpy(datagram, ip_packet+sizeof(sr_ip_hdr_t), DATAGRAM_SIZE);

      struct sr_icmp_t3_hdr* icmp_t3_hdr = createICMPt3hdr(icmp_type_dest_unreachable, 
        icmp_code_0,
        0,
        0,
        (uint8_t*)ip_hdr,
        IP_HDR_SIZE,
        datagram);

      createAndSendICMPPacket(sr, ethernet_hdr, (sr_ip_hdr_t*)ip_packet, (uint8_t *)icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    }
    else if (arp_entry != NULL) {
      /* Cache hit for ip_dst, forward the packet*/
      /*TODO it seems that icmp_t3_hdr does not exist in this scope*/
      /*createAndSendIPPacket(sr, ip_packet, ethernet_hdr->ether_dhost, arp_entry->mac, (uint8_t*) icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));*/
    } else {
      /* Entry for ip_dst missing in cache table, queue the packet*/
      char* iface = get_interface_from_mac(ethernet_hdr->ether_shost, sr);
      sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, ip_packet, ip_packet_len, iface);
    }
    free(arp_entry);
  }
}

void createAndSendIPPacket(struct sr_instance* sr, struct sr_ip_hdr* ip_packet, uint8_t* ether_source, uint8_t* ether_dest, uint8_t* ip_payload, uint8_t size) {

  /* Create ip packet by wrapping it over the payload*/
  sr_ip_hdr_t* ip_hdr = createIPHdr(ip_payload, 
      size, 
      ip_packet->ip_dst, 
      ip_packet->ip_src,
      ip_protocol_icmp);

  /* Create ethernet packet by wrapping it over the ip packet*/
  uint8_t * eth_hdr = createEthernetHdr(ether_source,
      ether_dest,
      ethertype_ip,
      (uint8_t *) ip_hdr,
      sizeof(struct eth_hdr*) + ip_hdr->ip_len);

  sr_send_packet(sr, eth_hdr, sizeof(eth_hdr), get_interface_from_mac(((sr_ethernet_hdr_t*)eth_hdr)->ether_dhost, sr));

  /* TODO: Free all memory and perform correct conversion of network <-> local endian type*/
}
