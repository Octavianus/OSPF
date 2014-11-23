/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>

// A list of all the neighbors.
struct neighbor_list
{
    struct in_addr neighbor_id;
    uint8_t alive; // in seconds
    struct neighbor_list* next;
}__attribute__ ((packed));

/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);
void add_neighbor(neighbor_list* nbr_head, neighbor_list* new_neighbor);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);


    /* -- handle subsystem initialization here! -- */


    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_lock(sr->ospf_subsys);
        printf(" pwospf subsystem sleeping \n");
        pwospf_unlock(sr->ospf_subsys);
        sleep(2);
        printf(" pwospf subsystem awake \n");
    };
} /* -- run_ospf_thread -- */

void handle_hello_packets(struct sr_instance* sr, struct sr_if* interface, uint8_t* packet, unsigned int length)
{


    bool exit_neighbor = true;
    uint16_t checksum = 0;
    struct in_addr neighbor_id;
    // Contruct the header.

	struct ip * iP_Hdr = ((ip *)(packet + sizeof(sr_ethernet_hdr)));
	struct ospfv2_hdr* ospfv2_Hdr = ((struct ospfv2_hdr *)(packet + sizeof(sr_ethernet_hdr) + sizeof(ip)));
    struct ospfv2_hello_hdr* ospfv2_Hello_Hdr = ((struct ospfv2_hello_hdr *)(packet + sizeof(sr_ethernet_hdr) + sizeof(ip) + sizeof(ospfv2_hdr)));

    neighbor_id.s_addr = ospfv2_Hdr->rid;
    struct in_addr net_mask;
    net_mask.s_addr = ospfv2_Hello_Hdr->nmask;
    Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet from:\n");
    Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));
    Debug("      [Neighbor IP = %s]\n", inet_ntoa(iP_Hdr->ip_src));
    Debug("      [Network Mask = %s]\n", inet_ntoa(net_mask));

    // Examine the checksum
    uint16_t rx_checksum = ospfv2_Hdr->csum;
    uint8_t * hdr_checksum = ((uint8_t *)(packet + sizeof(sr_ethernet_hdr) + sizeof(ip)));
    checksum = cal_ICMPcksum(hdr_checksum, sizeof(ospfv2_hello_hdr) + sizeof(ospfv2_hdr));
    if (checksum != rx_checksum)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid checksum\n");
        return;
    }

    // Examine the validation of the hello interval
    if (ospfv2_Hello_Hdr->helloint != 5)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello interval\n");
        return;
    }

    // Examine the interface mask
    if (ospfv2_Hello_Hdr->nmask != interface->mask)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello network mask\n");
        return;
    }

    // If it is already the neighbor of the interface
    if (interface->neighbor_id != ospfv2_Hdr->rid)
    {
    	exit_neighbor = false;
    	interface->neighbor_id = ospfv2_Hdr->rid;
    }
    interface->neighbor_ip = iP_Hdr->ip_src.s_addr;

    // give the header of the neighbor list and the neighbor id, and renew the neighbors' timestamp
    struct neighbor_list* ptr = nbr_head;
    while(ptr != NULL)
    {
    	if (ptr->neighbor_id.s_addr == neighbor_id.s_addr)
    	{
    		Debug("-> PWOSPF: Refreshing the neighbor, [ID = %s] in the alive neighbors table\n", inet_ntoa(neighbor_id));
    		ptr->alive = OSPF_NEIGHBOR_TIMEOUT;
    		return;
    	}

    	ptr = ptr->next;
    }

    Debug("-> PWOSPF: Adding the neighbor, [ID = %s] to the alive neighbors table\n", inet_ntoa(neighbor_id));

    // Create a new neighbor and add it to the list
    struct neighbor_list* new_neighbor = ((neighbor_list*)(malloc(sizeof(neighbor_list))));
    new_neighbor->neighbor_id.s_addr = neighbor_id.s_addr;
    new_neighbor->alive = OSPF_NEIGHBOR_TIMEOUT;
    new_neighbor->next = NULL;

    add_neighbor(nbr_head, new_neighbor);

    // send the lsu announcement to the internet of adding a new neighbor
    if (exit_neighbor == false)
    {
        struct powspf_hello_lsu_param* lsu_param = ((powspf_hello_lsu_param*)(malloc(sizeof(powspf_hello_lsu_param))));
        lsu_param->sr = sr;
        lsu_param->interface = interface;
        pthread_create(&lsu_thread, NULL, send_lsu, lsu_param);
    }
} /* -- handling_ospfv2_hello_packets -- */

