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
        unsigned int len/* Does not include ethernet header */,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  /* The ethernet packet*/
  assert(packet);
  /* The incoming interface*/
  assert(interface);

  /* fill in code here */

  sr_ethernet_hdr_t *ethernet_hdr = sr_copy_ethernet_packet(packet, len);
  /* Swap interface to hardware */
  struct sr_if* incoming_network_interface = sr_get_interface(sr, interface);
  struct sr_if* incoming_hardware_interface = sr_copy_interface(incoming_network_interface);
  struct sr_arp_hdr *arp_hdr = sr_copy_arp_hdr((uint8_t *) ethernet_hdr);

  /* If receive an ARP packet and we are recipient*/
  if (ethernet_hdr->ether_type == ethertype_arp && sr_is_packet_recipient(sr, arp_hdr->ar_tip)) {
    /* If ARP request, reply with our mac address*/
    if (arp_hdr->ar_op == arp_op_request) {
      sr_handle_arp_request(sr, ethernet_hdr, arp_hdr, incoming_hardware_interface);
    } else if (arp_hdr->ar_op == arp_op_reply){
      /* If ARP response, remove the ARP request from the queue, update cache, forward any packets that were waiting on that ARP request
      all Gorden's function*/
      receviedARPReply(sr, arp_hdr);
    }
    free(arp_hdr);
  } else if (ethernet_hdr->ether_type == ethertype_ip) {
    /* If receive an IP packet*/
    uint8_t *ip_packet = sr_copy_ip_packet((uint8_t *) ethernet_hdr, len - sizeof(struct sr_ethernet_hdr));
    /* Check if the received packet is valid, if not drop the packet*/
    if (sr_ip_packet_is_valid(ip_packet, len)) {
        if (sr_is_packet_recipient(sr, ((sr_ip_hdr_t*)ip_packet)->ip_dst)) {
          sr_handle_packet_reply(sr, ip_packet, ethernet_hdr);
        } 
        else {
          sr_handle_packet_forward(sr, ethernet_hdr, ip_packet, len - sizeof(struct sr_ethernet_hdr));
        }
    }
    /* Check if we are recipient of the packet*/
    free(ip_packet);
  }
  free(ethernet_hdr);
  free(incoming_hardware_interface);
}/* end sr_handlepacket */


/* Determine if the router contains the intended recipient of the ip packet*/
int sr_is_packet_recipient(struct sr_instance *sr, uint32_t ip) {
  /* The interfaces are represented as big endian */
  uint32_t network_ip = htonl(ip);
  
  struct sr_if* if_walker = sr->if_list;
  while(if_walker)
  {
    if(if_walker->ip == network_ip) { 
      return 1; 
    }
    if_walker = if_walker->next;
  }
  return 0;
}

/* Send back the MAC address of our incoming interface to the sender*/
void sr_handle_arp_request(struct sr_instance* sr, struct sr_ethernet_hdr *ethernet_hdr, struct sr_arp_hdr *arp_hdr, struct sr_if* out_interface) {

  struct sr_arp_hdr *arp_reponse_hdr = sr_create_arp_response_hdr(arp_hdr, out_interface->addr, out_interface->ip, arp_hdr->ar_sha, arp_hdr->ar_sip);
  
  sr_create_send_ethernet_packet(sr,
      out_interface->addr, 
      ethernet_hdr->ether_shost, 
      ethertype_arp, 
      (uint8_t *) arp_reponse_hdr, 
      sizeof(sr_arp_hdr_t));

  free(arp_reponse_hdr);
}

/* Set source ip, source MAC and target MAC of the ARP response header*/
struct sr_arp_hdr *sr_create_arp_response_hdr(struct sr_arp_hdr *arp_hdr, unsigned char *src_mac, uint32_t src_ip, unsigned char *dest_mac, uint32_t dest_ip) {

  unsigned int size = sizeof(sr_arp_hdr_t);
  sr_arp_hdr_t *arp_reponse_hdr = malloc(size);
  memcpy(arp_reponse_hdr, arp_hdr, size);

  memcpy(arp_reponse_hdr->ar_sha, src_mac, ETHER_ADDR_LEN);
  arp_reponse_hdr->ar_sip = src_ip;
  memcpy(arp_reponse_hdr->ar_tha, dest_mac, ETHER_ADDR_LEN);
  arp_reponse_hdr->ar_tip = dest_ip;
  arp_reponse_hdr->ar_op = arp_op_reply;

  transform_hardware_to_network_arp_header(arp_reponse_hdr);

  return arp_reponse_hdr;
}

/*  Check for packet minimum length and checksum*/
int sr_ip_packet_is_valid(uint8_t *ip_packet, unsigned int ip_packet_len) {
  uint16_t cksum = get_network_cksum_from_hardware_ip(ip_packet, IP_HDR_SIZE);

  int valid = ip_packet_len >= IP_HDR_SIZE && cksum == 0xffff;

  return valid;
}

void sr_handle_packet_reply(struct sr_instance* sr, uint8_t *ip_packet, struct sr_ethernet_hdr* ethernet_hdr) {
  /* When replying, simply swap the original ip/mac values */
  struct sr_ip_hdr* ip_hdr = (sr_ip_hdr_t*) ip_packet;  
  uint32_t ip_src = ip_hdr->ip_dst;
  uint32_t ip_dest = ip_hdr->ip_src;
  uint8_t* eth_src = ethernet_hdr->ether_dhost;
  uint8_t* eth_dest = ethernet_hdr->ether_shost;
  sr_object_t icmp_wrapper;

  /* Return a port unreachable for UDP or TCP type packets through a icmp_t3_header*/
  if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
    icmp_wrapper = create_icmp_t3_packet(icmp_type_dest_unreachable, icmp_code_3, 0, ip_packet);
  } else if (ip_hdr->ip_p == ip_protocol_icmp) {
    /* Return a echo reply for echo request*/
    unsigned int headers_size = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t* icmp_payload = ip_packet + headers_size;
    icmp_wrapper = create_icmp_packet(icmp_type_echo_reply, icmp_code_0, icmp_payload, ip_hdr->ip_len - headers_size);
  }

  /* Only perform replies when handling a valid reply action */
  if (icmp_wrapper.packet != NULL) {
    /* Determine the destination to reply to first through the arp cache */
    struct sr_rt* longestPrefixIPMatch = getInterfaceLongestMatch(sr->routing_table,ip_hdr->ip_src);
    uint32_t nextHopIPHardware = ntohl(longestPrefixIPMatch->gw.s_addr); 
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), nextHopIPHardware);

    /* Send destination unreachable if reply destination is not in the forwarding table */
    if (longestPrefixIPMatch == NULL) {
      sr_object_t icmp_t3_wrapper = create_icmp_t3_packet(icmp_type_dest_unreachable, icmp_code_0, 0, ip_packet);
      createAndSendIPPacket(sr, ip_src, ip_dest, eth_src, eth_dest, icmp_t3_wrapper.packet, icmp_t3_wrapper.len);

      free(icmp_t3_wrapper.packet);
    } else if (arp_entry == NULL) {
      /* Send an arp request if we do not have the reply destination cached */
      sr_object_t ip_wrapper = create_ip_packet(ip_protocol_icmp, ip_src, ip_dest, icmp_wrapper.packet, icmp_wrapper.len);
      sr_object_t eth_wrapper = create_ethernet_packet(eth_src, eth_dest, ethertype_ip, ip_wrapper.packet, ip_wrapper.len);
      sr_arpcache_queuereq(&(sr->cache), nextHopIPHardware, eth_wrapper.packet, eth_wrapper.len, longestPrefixIPMatch->interface);

      free(ip_wrapper.packet);
      free(eth_wrapper.packet);
    } else {
      /* Send out reply normally if the destination is cached */
      struct sr_if* outgoing_interface = sr_get_interface(sr, longestPrefixIPMatch->interface);
      eth_src = outgoing_interface->addr;
      eth_dest = arp_entry->mac;

      uint8_t* hardware_ether_src = malloc(6);
      memcpy(hardware_ether_src, eth_src, 6);
      swap_mac(hardware_ether_src);
      createAndSendIPPacket(sr, ip_src, ip_dest, hardware_ether_src, eth_dest, icmp_wrapper.packet, icmp_wrapper.len);
      free(hardware_ether_src);
    }

    free(icmp_wrapper.packet);
  }
}

void sr_handle_packet_forward(struct sr_instance *sr, struct sr_ethernet_hdr *ethernet_hdr, uint8_t *ip_packet, unsigned int ip_packet_len) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_packet;

  /* Initialize packet src/dest with 'reply' type values*/
  struct sr_rt* icmp_rt = getInterfaceLongestMatch(sr->routing_table, ip_hdr->ip_src);

  struct sr_if *icmp_outgoing_interface = sr_get_interface(sr, icmp_rt->interface);
  uint32_t ip_src = ntohl(icmp_outgoing_interface->ip);
  uint32_t ip_dest = ip_hdr->ip_src;
  uint8_t* eth_src = ethernet_hdr->ether_dhost;
  uint8_t* eth_dest = ethernet_hdr->ether_shost;
  unsigned int ip_hdr_size = sizeof(sr_ip_hdr_t);


  if (ip_hdr->ip_ttl <= 1) {
    /* Send ICMP time exceeded*/
    sr_object_t icmp_t3_wrapper = create_icmp_t3_packet(icmp_time_exceeded, icmp_code_0, 0, ip_packet);

    createAndSendIPPacket(sr, ip_src, ip_dest, eth_src, eth_dest, icmp_t3_wrapper.packet, icmp_t3_wrapper.len);
  } else {


    /* Get the MAC address of next hub*/
    struct sr_rt* longestPrefixIPMatch = getInterfaceLongestMatch(sr->routing_table,ip_hdr->ip_dst);
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);

    /* Send ICMP network unreachable if the ip cannot be identified through our routing table */
    if (longestPrefixIPMatch == NULL) {
      sr_object_t icmp_t3_wrapper = create_icmp_t3_packet(icmp_type_dest_unreachable, icmp_code_0, 0, ip_packet);
      createAndSendIPPacket(sr, ip_src, ip_dest, eth_src, eth_dest, icmp_t3_wrapper.packet, icmp_t3_wrapper.len);
    } else {
    /* Update IP packet checksum */
      ip_hdr->ip_ttl -= 1;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = get_network_cksum_from_hardware_ip(ip_packet, ip_hdr_size);

      if (arp_entry == NULL) {
        /* Entry for ip_dst missing in cache table, queue the packet*/
        queue_ethernet_packet(sr, ip_packet, ip_packet_len);
      } else {
        /* When forwarding to next-hop, only mac addresses change*/
        struct sr_if* outgoing_interface = sr_get_interface(sr, longestPrefixIPMatch->interface);
        eth_src = outgoing_interface->addr;
        eth_dest = arp_entry->mac;

        uint8_t* hardware_ether_src = malloc(6);
        memcpy(hardware_ether_src, eth_src, 6);
        swap_mac(hardware_ether_src);

        transform_hardware_to_network_ip_header((sr_ip_hdr_t*)ip_packet);
        sr_create_send_ethernet_packet(sr, hardware_ether_src, eth_dest, ethertype_ip, ip_packet, ip_packet_len);

        free(hardware_ether_src);
      }
    }
    free(arp_entry);
  }
}

void queue_ethernet_packet(struct sr_instance *sr, uint8_t *ip_packet, unsigned int ip_packet_len) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_packet;

  struct sr_rt* rt = getInterfaceLongestMatch(sr->routing_table, ip_hdr->ip_dst);
  uint32_t hardware_ip_dst = ip_hdr->ip_dst;

  transform_hardware_to_network_ip_header(ip_hdr);

  uint8_t* empty_ether_shost = malloc(6);
  sr_object_t ethernet_packet = create_ethernet_packet(empty_ether_shost, empty_ether_shost, ethertype_ip, ip_packet, ip_packet_len);
  free(empty_ether_shost);

  sr_arpcache_queuereq(&(sr->cache), hardware_ip_dst, ethernet_packet.packet, ethernet_packet.len, rt->interface);
}

/* Create an Ethernet packet and send it, len = size of data in bytes*/
void sr_create_send_ethernet_packet(struct sr_instance* sr, uint8_t* ether_shost, uint8_t* ether_dhost, uint16_t ethertype, uint8_t *data, uint16_t len) {
  char* outgoing_interface = get_interface_from_mac(ether_shost, sr);
  sr_object_t ethernet_packet = create_ethernet_packet(ether_shost, ether_dhost, ethertype, data, len);

  sr_send_packet(sr, ethernet_packet.packet, 
                ethernet_packet.len, 
                outgoing_interface);

  free(ethernet_packet.packet);
}


/* Should pass in correct ip*/
void createAndSendIPPacket(struct sr_instance* sr, uint32_t ip_src, uint32_t ip_dest, uint8_t* eth_src, uint8_t* eth_dest, uint8_t* ip_payload, uint8_t len) {
  /* Create ip packet by wrapping it over the payload*/
  sr_object_t ip_wrapper = create_ip_packet(ip_protocol_icmp,
      ip_src,
      ip_dest,
      ip_payload,
      len);

  /* Create ethernet packet by wrapping it over the ip packet*/
  sr_object_t eth_wrapper = create_ethernet_packet(eth_src,
      eth_dest,
      ethertype_ip,
      ip_wrapper.packet,
      ip_wrapper.len);

  sr_send_packet(sr, eth_wrapper.packet, eth_wrapper.len, get_interface_from_mac(eth_src, sr));

  free(eth_wrapper.packet);
}


/* TODO: Conver from network to hardwarr byte order*/
/* Copy the header from the Ethernet packet*/
sr_ethernet_hdr_t *sr_copy_ethernet_packet(uint8_t *ethernet_packet, unsigned int len) {
  /*unsigned int size = sizeof(struct sr_ethernet_hdr) + len;*/
  struct sr_ethernet_hdr* ethernet_hdr  = malloc(len);
  memcpy(ethernet_hdr, ethernet_packet, len);
  transform_network_to_hardware_ethernet_header(ethernet_hdr);
  return ethernet_hdr;
}


/* Copy the header from the ARP packet*/
sr_arp_hdr_t *sr_copy_arp_hdr(uint8_t *ethernet_packet) {
  struct sr_arp_hdr* arp_hdr  = malloc(sizeof(struct sr_arp_hdr));
  memcpy(arp_hdr, ethernet_packet + ETHERNET_HDR_SIZE, sizeof(sr_arp_hdr_t));
  transform_network_to_hardware_arp_header(arp_hdr);
  return arp_hdr;
}


/* Copy the IP packet from the Ethernet packet*/
uint8_t *sr_copy_ip_packet(uint8_t *ethernet_packet, unsigned int ip_packet_len) {
  uint8_t *ip_packet = malloc(ip_packet_len);
  memcpy(ip_packet, ethernet_packet + sizeof(sr_ethernet_hdr_t), ip_packet_len);
  transform_network_to_hardware_ip_header((sr_ip_hdr_t *)ip_packet);
  return ip_packet;
}

/* Copy the interface and initialize it in hardware order*/
struct sr_if *sr_copy_interface(struct sr_if *interface) {
  unsigned int size = sizeof(struct sr_if);
  struct sr_if *interface_copy = malloc(size);

  memcpy(interface_copy, interface, size);
  transform_network_to_hardware_sr_if(interface_copy);
  return interface_copy;
} 
