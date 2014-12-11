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

/* forward declare */
struct sr_instance;

// A list of all the neighbors.
struct neighbor_list
{
    uint8_t alive; // in seconds
    struct in_addr neighbor_id;
    struct neighbor_list* next;
}__attribute__ ((packed));

struct neighbor_list* nbr_head;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */


    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

int pwospf_init(struct sr_instance* sr);


#endif /* SR_PWOSPF_H */
