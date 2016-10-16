#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "s.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/



void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */

    /* I don't think lock is needed*/
    struct sr_arpcache cache = sr->cache;
    struct sr_arpreq* currReq = cache.requests;
    struct sr_arpreq* currReqCpy = currReq;
    while(currReq != NULL){
        currReqCpy = currReq;
        currReq = currReq->next;
        handle_arpreq(currReq, sr);
    }
}

void handle_arpreq(struct sr_arpreq* req, struct sr_instance* sr){
    
    /*WARNING MAY NOT WORK IF THE FIRST PACKET in req->packets is EMPTY.8?*/

    /*this is a linked list of packets depending on the ARP request*/
    struct sr_packet *packet = req->packets;

    time_t curtime = time(NULL);
    if(difftime(curtime, req->sent) > 1.0){
        if(req->times_sent >= 5){
            /*sent ICMP unreachable to all packets waiting on this ARPReq*/
            while(packet != NULL){

                if(packet->len < sizeof(sr_ethernet_hdr_t)){
                    fprintf(stderr, "Packet ignored due to length (short)\n");
                    packet = packet->next;
                    continue;
                }

                /*NEED TO CHECK IF RAW ETHERNET FRAME HAS 8 BYTE PREAMBLE */
                sr_ethernet_hdr_t* currEthHdr = (sr_ethernet_hdr_t*) packet->buf;
                if(currEthHdr->ether_type != ethertype_ip){
                    fprintf(stderr, "Packet ignored due to unrecognized ether type: %d\n",currEthHdr->ether_type);
                    packet = packet->next;
                    continue;
                }

                char *outgoingInterface = get_interface_from_mac(currEthHdr->ether_dhost, sr);
                if(!outgoingInterface){
                    fprintf(stderr, "Packet ignored due to not being able to find outgoing interface.\n");
                    packet = packet->next;
                    continue;
                }

                /*need to verify*/
                sr_ip_hdr_t* currIPHdr = (sr_ip_hdr_t*) &(packet->buf[sizeof(sr_ethernet_hdr_t)]);
                uint8_t* datagram = malloc(8);
                memcpy(datagram, &packet->buf[sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)], 8);
                uint32_t imcp_destination = ntohl(currIPHdr->ip_src);

                struct sr_rt* targetRT = getInterfaceLongestMatch(sr->routing_table, imcp_destination);
                struct sr_if *targetInterface = sr_get_interface(sr, targetRT->interface);

                uint32_t IPSrc = htonl(targetInterface->ip);

                sr_icmp_t3_hdr_t* sendICMPPacket = createICMPt3hdr(3,1,0,0, (uint8_t*)currIPHdr,sizeof(sr_ip_hdr_t), datagram);
                sr_ip_hdr_t* sendIPHeader = createIPHdr((uint8_t*)sendICMPPacket,sizeof(sr_icmp_t3_hdr_t), IPSrc, imcp_destination, ip_protocol_icmp);
                uint8_t* sendEthernet = createEthernetHdr(currEthHdr->ether_shost, currEthHdr->ether_dhost,
                                    ethertype_ip, (uint8_t*)sendIPHeader, sizeof(sendIPHeader)+sizeof(sendICMPPacket));

                sr_send_packet(sr, sendEthernet, sizeof(sr_ethernet_hdr_t)+sizeof(sendIPHeader)+sizeof(sendICMPPacket),outgoingInterface);
                /*create ICMP packet and send it*/

                packet = packet->next;
            }
            sr_arpreq_destroy(&sr->cache, req);
        }
        else{/*req->times_sent <= 5*/

            struct sr_rt* rt;
            rt = get_Node_From_RoutingTable(sr, req->ip);
            if(!rt){
                fprintf(stderr, "problem\n");
            }
            
            struct sr_if* sr_if = sr_get_interface(sr, rt->interface);
            sr_arp_hdr_t *newArpReq = createARPReqHdr(sr, req, sr_if);
            if(!newArpReq){
                fprintf(stderr, "problem\n");
            }

            uint32_t broadcastAddr= 0xFFFFFFFF;

            uint8_t *arp_packet = createEthernetHdr(
                broadcastAddr, newArpReq->ar_sha, ethertype_arp, (uint8_t*)newArpReq, sizeof(sr_arp_hdr_t));
            sr_send_packet(sr, (uint8_t *) arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), sr_if->name);
            req->sent = time(NULL);
            req->times_sent++;
        }

    }
}

sr_arp_hdr_t *createARPReqHdr(struct sr_instance* sr, struct sr_arpreq *req, struct sr_if* sr_if) {
  sr_arp_hdr_t *output = malloc(sizeof(sr_arp_hdr_t));

  output->ar_hrd = htons(0x0001);
  output->ar_pro = htons(ethertype_ip);
  output->ar_hln = 0x0006;
  output->ar_pln = 0x0004;
  output->ar_op = htons(arp_op_request);
  output->ar_sip = sr_if->ip;
  
  memcpy(&output->ar_tha[0], &sr_if->addr[0], ETHER_ADDR_LEN);

  output->ar_tip = req->ip;

  return output;
}

struct sr_rt* get_Node_From_RoutingTable(struct sr_instance* sr, uint32_t ip){

  struct sr_rt *rt = sr->routing_table;

  while(rt) {
    if (rt->gw.s_addr == ip) {
      return rt;
    }
    rt = rt->next;
  }
return NULL;
}

char* get_interface_from_mac(uint8_t *ether_shost, struct sr_instance* sr){
    struct sr_if* interfaceList = sr->if_list;
    int i;
    while(interfaceList){

        /*compare*/ 
        for(i = 0; i<ETHER_ADDR_LEN; i++){
            if(interfaceList->addr[i] !=  ether_shost[i]){
                break;
            }
        }
        if(i == ETHER_ADDR_LEN - 1){
            return interfaceList->name;
        }
        interfaceList = interfaceList->next;
    }
    return NULL;
}

void receviedARPReply(struct sr_instance* sr, sr_arp_hdr_t* ARPReply){

    unsigned char* replyAddr = ARPReply->ar_sha;
    uint32_t replyIP = ARPReply->ar_sip;

    struct sr_arpreq *arpreq = sr_arpcache_insert(sr->*cache,replyAddr,replyIP);
    if(arpreq){
        struct sr_packet* = arpreq->packets;
        while(packets){
            memcpy(packets->buf, replyAddr, ETHER_ADDR_LEN);
            char* interface = get_interface_from_mac(replyAddr, sr);
            sr_send_packet(sr , packets->buf , packets->len, interface);
            packets = packets.next;
        }
    }

}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

