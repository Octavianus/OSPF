/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_router.h"
#include "sr_protocol.h"

/* forward declare */
struct sr_instance;
in_addr router_id;

pthread_t T_hello;
pthread_t T_neighbor;
pthread_t T_dijkstra;

// Mutex lock for the dijkstra calculation look
pthread_mutex_t mutex_lock_dijkstra = PTHREAD_MUTEX_INITIALIZER;

// A list of all the neighbors.
struct neighbor_list
{
    uint8_t alive; // in seconds
    struct in_addr neighbor_id;
    struct neighbor_list* next;
}__attribute__ ((packed));

struct neighbor_list* nbr_head;

struct route_dijkstra_node
{
    // TODO struct ospfv2_topology_entry* topology_entry;
    struct route_dijkstra_node* next;
    struct route_dijkstra_node* prev;
    uint8_t dist;
} __attribute__ ((packed)) ;

struct route_dijkstra_node* dijkstra_stack;
struct route_dijkstra_node* dijkstra_heap;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */


    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

struct pwospf_topology_entry
{
    struct in_addr router_id;       /* router id */
    struct in_addr subnet_ip;       /* subnetwork prefix */
    struct in_addr subnet_mask;      /* subnetwork mask */
    struct in_addr neighbor_id;     /* neighbour router id */
   // struct in_addr next_hop;        /* next hop */
    uint16_t sequence_num;         /* sequence number of the related LSU */
    int time_stamp;                       /* the timestamp of this advertised link */
    struct pwospf_topology_entry* next;
}__attribute__ ((packed));

struct pwospf_topology_entry* topology_header;

int pwospf_init(struct sr_instance* sr);


#endif /* SR_PWOSPF_H */
