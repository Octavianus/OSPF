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
#include "neighbor.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>

bool if_unable;
static const uint8_t OSPF_DEFAULT_HELLOINT = 5;

struct sr_if_packet
{
	struct sr_instance* sr;
	struct sr_if* interface;
}__attribute__ ((packed));

/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);
void add_neighbor(neighbor_list* nbr_head, neighbor_list* new_neighbor);
void handle_hello_packets(struct sr_instance* sr, struct sr_if* interface, uint8_t* packet, unsigned int length);
void hello_messages_thread(struct sr_instance *sr);
void* hello_message(sr_if_packet * sr_if_pk);
void* scan_neighbor_list(void* thread);
void dijkstra_stack_push(struct route_dijkstra_node* dijkstra_first_item, struct route_dijkstra_node* dijkstra_new_item);
struct route_dijkstra_node* dijkstra_stack_pop(struct route_dijkstra_node* dijkstra_first_item);
struct route_dijkstra_node* create_dikjstra_item(struct pwospf_topology_entry* new_topology_entry, uint8_t dist);
void* run_dijkstra(struct sr_instance* sr);

uint8_t hello_broadcast_addr[ETHER_ADDR_LEN];

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

	sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct pwospf_subsys));

	assert(sr->ospf_subsys);
	pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
	if_unable = false;

	// nbr list header pointer and init header address.
	struct in_addr header_addr;
	header_addr.s_addr = 0;
	nbr_head = NULL;
	nbr_head = ((neighbor_list*)(malloc(sizeof(neighbor_list))));
	nbr_head->neighbor_id.s_addr = header_addr.s_addr;
	nbr_head->alive = OSPF_NEIGHBOR_TIMEOUT;
	nbr_head->next = NULL;

	// ALLSPFRouters that is defined as "224.0.0.5" (0xe0000005)
	hello_broadcast_addr[0] = 0x01;
	hello_broadcast_addr[1] = 0x00;
	hello_broadcast_addr[2] = 0xe0;
	hello_broadcast_addr[3] = 0x00;
	hello_broadcast_addr[4] = 0x00;
	hello_broadcast_addr[5] = 0x05;
	/* -- handle subsystem initialization here! -- */

	topology_header = create_ospfv2_topology_entry(header_addr, header_addr, header_addr, header_addr, header_addr, 0);

	/* -- start thread subsystem -- */
	if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
		perror("pthread_create");
		assert(0);
	}

	if( pthread_create(&T_hello, NULL, hello_messages_thread, sr)) {
		perror("pthread_create");
		assert(0);
	}

	if( pthread_create(&T_neighbor, NULL, scan_neighbor_list, NULL)) {
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

/*------------------------------------------------------------------------------------
 * Method: handle_hello_packets(struct sr_instance* sr,
 * struct sr_if* interface,
 * uint8_t* packet,
 * unsigned int length)
 * Handle the hello packets that send from other routers.
 *-----------------------------------------------------------------------------------*/
void handle_hello_packets(struct sr_instance* sr, struct sr_if* interface, uint8_t* packet, unsigned int length)
{
	bool exit_neighbor = true;
	uint16_t checksum = 0;
	struct in_addr neighbor_id;
	// Contruct the header.

	struct ip * iP_Hdr = NULL;
	iP_Hdr = (ip *)(packet + sizeof(sr_ethernet_hdr));
	struct ospfv2_hdr* ospfv2_Hdr = (struct ospfv2_hdr *)(packet + sizeof(sr_ethernet_hdr) + sizeof(ip));
	struct ospfv2_hello_hdr* ospfv2_Hello_Hdr = (struct ospfv2_hello_hdr *)(packet + sizeof(sr_ethernet_hdr) + sizeof(ip) + sizeof(ospfv2_hdr));

	neighbor_id.s_addr = ospfv2_Hdr->rid;
	struct in_addr net_mask;
	net_mask.s_addr = ospfv2_Hello_Hdr->nmask;
	Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet from:\n");
	Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));
	Debug("      [Neighbor IP = %s]\n", inet_ntoa(iP_Hdr->ip_src));
	Debug("      [Network Mask = %s]\n", inet_ntoa(net_mask));

	// Examine the checksum
	uint16_t rx_checksum = ospfv2_Hdr->csum;
	uint8_t * hdr_checksum = (uint8_t *)(packet + sizeof(sr_ethernet_hdr) + sizeof(ip));
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
	// TODO add neighbor_id to the list
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

	// Create a new neighbor and malloc memory for it, and add it to the list
	struct neighbor_list* new_neighbor = (neighbor_list*)(malloc(sizeof(neighbor_list)));
	new_neighbor->neighbor_id.s_addr = neighbor_id.s_addr;
	new_neighbor->alive = OSPF_NEIGHBOR_TIMEOUT;
	new_neighbor->next = NULL;
	// sub function of creat a new neib, memory for new neighbor is allocated
	add_neighbor(nbr_head, new_neighbor);

	// send the lsu announcement to the internet of adding a new neighbor
	if (exit_neighbor == false)
	{
		struct sr_if_packet* lsu_param = (sr_if_packet*)(malloc(sizeof(sr_if_packet)));
		lsu_param->sr = sr;
		lsu_param->interface = interface;
		pthread_create(&lsu_thread, NULL, send_lsu, lsu_param);
	}
}

/*------------------------------------------------------------------------------------
 * Method: hello_messages_thread(struct sr_instance *sr)
 * Periodically check the interface list of the router to decide whether to send hello
 *-----------------------------------------------------------------------------------*/
void hello_messages_thread(struct sr_instance *sr)
{
	//struct sr_instance* sr = (struct sr_instance*)arg;

	while(1)
	{
		sleep(OSPF_DEFAULT_HELLOINT);
		pwospf_lock(sr->ospf_subsys);

		// Interate all the interface
		struct sr_if* if_walker = sr->if_list;
		while(if_walker != NULL)
		{
			// Check if this interface is down
			if (if_unable == true)
			{
				// Skip this down interface
				if (strcmp(if_walker->name, sr->f_interface) == 0)
				{
					if_walker = if_walker->next;
					continue;
				}
			}

			// Reduce the helloint of the unreceived interface
			if (if_walker->helloint > 0)
			{
				if_walker->helloint--;
			}
			else
			{
				// send hello packet.
				struct sr_if_packet* sr_if_pk = (sr_if_packet*)(malloc(sizeof(sr_if_packet)));
				sr_if_pk->sr = sr;
				sr_if_pk->interface = if_walker;
				pthread_create(&T_hello, NULL, hello_message, sr_if_pk); // void sr_if_pk
				//pthread_create( &thread, NULL, Arp_Cache_Timeout, (void*)&sr_if_pk);

				if_walker->helloint = OSPF_DEFAULT_HELLOINT;
			}

			if_walker = if_walker->next;
		}

		pwospf_unlock(sr->ospf_subsys);
	};

}

/*------------------------------------------------------------------------------------
 * Method: hello_message(sr_if_packet * sr_if_pk)
 * Detail to build the packet and send it by calling sr_send_packet.
 *-----------------------------------------------------------------------------------*/
void* hello_message(sr_if_packet * sr_if_pk)
{
	uint8_t* hello_packet = NULL;
	hello_packet = ((uint8_t*)(malloc(packet_len)));

	int packet_len = sizeof(sr_ethernet_hdr) + sizeof(ip) + sizeof(ospfv2_hdr) + sizeof(ospfv2_hello_hdr);
	Debug("\n\nPWOSPF: Constructing HELLO packet for interface %s: \n", sr_if_pk->interface->name);

	struct sr_ethernet_hdr* eth_hdr = (sr_ethernet_hdr*)(malloc(sizeof(sr_ethernet_hdr)));
	struct ip* ip_hdr = (ip*)(malloc(sizeof(ip)));
	struct ospfv2_hdr* ospf_hdr = (ospfv2_hdr*)(malloc(sizeof(ospfv2_hdr)));
	struct ospfv2_hello_hdr* hello_hdr = (ospfv2_hello_hdr*)(malloc(sizeof(ospfv2_hello_hdr)));

	// Copy the destination and source mac address from the target.
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		eth_hdr->ether_dhost[i] = hello_broadcast_addr[i];
		eth_hdr->ether_shost[i] = (uint8_t)(sr_if_pk->interface->addr[i]);
	}

	eth_hdr->ether_type = htons(ETHERTYPE_IP);
	ip_hdr->ip_v = (sizeof(struct ip))/4;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons((sizeof(ip)) + sizeof(ospfv2_hdr) + sizeof(ospfv2_hello_hdr));

	ip_hdr->ip_id = 0; /* 0 */
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 89; // OSPFv2

	ip_hdr->ip_src.s_addr = sr_if_pk->interface->ip;
	ip_hdr->ip_dst.s_addr = htonl(OSPF_AllSPFRouters);

	/* Re-Calculate checksum of the IP header */
	ip_hdr->ip_sum = cal_ICMPcksum((uint8_t*)(ip_hdr), sizeof(ip));
	ospf_hdr->version = OSPF_V2;
	ospf_hdr->type = OSPF_TYPE_HELLO;
	ospf_hdr->len = htons(sizeof(ospfv2_hdr) + sizeof(ospfv2_hello_hdr));
	ospf_hdr->rid = router_id.s_addr;    //It is the highest IP address on a router [according to Cisco]
	ospf_hdr->aid = htonl(171); //TODO now the area id dynamically
	ospf_hdr->csum = 0;
	ospf_hdr->autype = 0;
	ospf_hdr->audata = 0;
	hello_hdr->nmask = htonl(0xfffffffe);
	hello_hdr->helloint = htons(OSPF_DEFAULT_HELLOINT);
	hello_hdr->padding = 0;

	// Create the packet
	// Copy the content to the packet.
	memcpy(hello_packet, eth_hdr, sizeof(sr_ethernet_hdr));
	memcpy(hello_packet + sizeof(sr_ethernet_hdr), ip_hdr, sizeof(ip));
	memcpy(hello_packet + sizeof(sr_ethernet_hdr) + sizeof(ip), ospf_hdr, sizeof(ospfv2_hdr));
	memcpy(hello_packet + sizeof(sr_ethernet_hdr) + sizeof(ip) + sizeof(ospfv2_hdr), hello_hdr, sizeof(ospfv2_hello_hdr));

	// Update the ospf2 header checksum.
	uint8_t * temp_packet = hello_packet + sizeof(sr_ethernet_hdr) + sizeof(ip);
	ospf_hdr->csum = calc_chsum(temp_packet, sizeof(ospfv2_hdr) + sizeof(ospfv2_hello_hdr));
	ospf_hdr->csum = htons(ospf_hdr->csum);
	//(ospfv2_hdr*)(hello_packet + sizeof(sr_ethernet_hdr) + sizeof(ip))->csum =
	//    calc_cksum(hello_packet + sizeof(sr_ethernet_hdr) + sizeof(ip), sizeof(ospfv2_hdr) + sizeof(ospfv2_hello_hdr));

	Debug("-> PWOSPF: Sending HELLO Packet of length = %d, out of the interface: %s\n", packet_len, sr_if_pk->interface->name);
	sr_send_packet(sr_if_pk->sr, (uint8_t*)(hello_packet), packet_len, sr_if_pk->interface->name);

}

/*------------------------------------------------------------------------------------
 * Method: scan_neighbor_list(void* thread)
 * Scan the neighbor list, check if neighbors are alive or deleted them for the list.
 *-----------------------------------------------------------------------------------*/
void* scan_neighbor_list(void* thread)
{
	while(1)
	{
		usleep(1000000);

		struct ospfv2_neighbor* tmp_walker = nbr_head;

		while(tmp_walker != NULL)
		{
			// If there is no neighbor in this interface, break from the scan.
			if (tmp_walker->next == NULL)
			{
				break;
			}

			// if the alive is zero then delete the neighbor from the list.
			if (tmp_walker->next->alive == 0)
			{
				Debug("\n\n**** PWOSPF: Removing the neighbor, [ID = %s] from the alive neighbors table\n\n", inet_ntoa(ptr->next->neighbor_id));

				neighbor_list* delete_neighbor = tmp_walker->next;

				if (tmp_walker->next->next != NULL)
				{
					tmp_walker->next = tmp_walker->next->next;
				}
				else
				{
					tmp_walker->next = NULL;
				}

				free(delete_neighbor);
			}
			else
			{
				// else deduce the alive for one.
				tmp_walker->next->alive--;
			}

			tmp_walker = tmp_walker->next;
		}
	};

}

/*------------------------------------------------------------------------------------
 * Method: dijkstra_stack_push(struct route_dijkstra_node* dijkstra_first_item, struct route_dijkstra_node* dijkstra_new_item)
 * Push a visited node into the stack structure to calculate the dijkstra
 *-----------------------------------------------------------------------------------*/
void dijkstra_stack_push(struct route_dijkstra_node* dijkstra_first_item, struct route_dijkstra_node* dijkstra_new_item)
{
	if (dijkstra_first_item->next != NULL)
	{
		dijkstra_new_item->next = dijkstra_first_item->next;
		dijkstra_first_item->next = dijkstra_new_item;
	}

	dijkstra_first_item->next = dijkstra_new_item;
}

/*------------------------------------------------------------------------------------
 * Method: dijkstra_stack_pop(struct route_dijkstra_node* dijkstra_first_item)
 * Pop a visited node into the stack structure to calculate the dijkstra
 *-----------------------------------------------------------------------------------*/
struct route_dijkstra_node* dijkstra_stack_pop(struct route_dijkstra_node* dijkstra_first_item)
{
	if (dijkstra_first_item->next == NULL)
	{
		return NULL;
	}
	else
	{
		struct route_dijkstra_node* pResult = dijkstra_first_item->next;

		dijkstra_first_item->next = dijkstra_first_item->next->next;

		return pResult;
	}
}

/*------------------------------------------------------------------------------------
 * Method: create_dikjstra_item(struct pwospf_topology_entry* new_topology_entry, uint8_t dist)
 * Create a new dijkstra list to save the router's node.
 *-----------------------------------------------------------------------------------*/
struct route_dijkstra_node* create_dikjstra_item(struct pwospf_topology_entry* new_topology_entry, uint8_t dist)
{
	struct route_dijkstra_node* dijkstra_new_item = ((route_dijkstra_node*)(malloc(sizeof(route_dijkstra_node))));
	dijkstra_new_item->topology_entry = new_topology_entry;
	dijkstra_new_item->dist = dist;
	dijkstra_new_item->prev = NULL;
	dijkstra_new_item->next = NULL;
	return dijkstra_new_item;
}

/*---------------------------------------------------------------------
 * Method: run_dijkstra(struct sr_instance* sr)
 *
 * Run Dijkstra algorithm, Let the node at which we are starting be
 * called the initial node. Let the distance of node Y be the distance from the initial node to Y.
 *---------------------------------------------------------------------*/

void* run_dijkstra(struct sr_instance* sr)
{
	// Mutex lock for the dijkstra calculation look}
	pthread_mutex_lock(&mutex_lock_dijkstra);

	struct in_addr zero;
	zero.s_addr = 0;
	dijkstra_stack = create_dikjstra_item(create_pwospf_topology_entry(zero, zero, zero, zero, zero, 0), 0);
	dijkstra_heap = create_dikjstra_item(create_pwospf_topology_entry(zero, zero, zero, zero, zero, 0), 0);
	/* Cleaing the routing table */
	// TODO
	clear_routes(sr);

	struct sr_rt* entry = sr->routing_table;
	while(entry/*->next*/ != NULL)
	{
		//printf("entry: %s\t", inet_ntoa(entry->dest));
		if (entry->next == NULL)
		{
			break;
		}
		//printf("entry->next: %s\n", inet_ntoa(entry->next->dest));
		if (entry->next->admin_dst > 1)
		{
			sr_del_rt_entry(entry);
		}
		else
		{
			entry = entry->next;
		}
	}


	/* Run Dijkstra algorithm */
	struct pwospf_topology_entry* topo_entry = topology_header->next;
	while(topo_entry != NULL)
	{
		if (check_route(sr, topo_entry->net_num) == 0)
		{
			struct sr_if* temp_int = sr->if_list;
			while (temp_int != NULL)
			{

				if (search_topolgy_table(topology_header, (temp_int->ip & htonl(0xfffffffe))) == 0)
				{
					temp_int = temp_int->next;
					continue;
				}

				if (temp_int->neighbor_id != 0)
				{
					struct in_addr mask;	    mask.s_addr = htonl(0xfffffffe);
					struct in_addr subnet;	    subnet.s_addr = temp_int->ip & mask.s_addr;
					struct in_addr neighbor_id;	    neighbor_id.s_addr = temp_int->neighbor_id;
					struct in_addr next_hop;	    next_hop.s_addr = temp_int->neighbor_ip;

					dijkstra_stack_push(dijkstra_heap, create_dikjstra_item(create_pwospf_topology_entry(router_id, subnet, mask, neighbor_id,
							next_hop, 0), 1));
				}

				temp_int = temp_int->next;
			}

			struct route_dijkstra_node* dijkstra_popped_item;
			uint8_t stop = 0;
			while(1)
			{
				while(1)
				{
					/* Pop from the heap */
					dijkstra_popped_item = dijkstra_stack_pop(dijkstra_heap);

					if (dijkstra_popped_item == NULL)
					{
						stop = 1;
						break;
					}

					if (dijkstra_popped_item->topology_entry->net_num.s_addr == topo_entry->net_num.s_addr)
					{
						stop = 1;
						break;
					}

					if (dijkstra_popped_item->topology_entry->neighbor_id.s_addr != 0)
					{
						break;
					}
				}

				/* Push popped item in stack */
				if (dijkstra_popped_item != NULL)
				{
					dijkstra_stack_push(dijkstra_stack, dijkstra_popped_item);
				}


				/* stopping criteria here */
				if (stop == 1)
				{
					break;
				}


				/* Relaxing the popped item */
				struct pwospf_topology_entry* ptr = topology_header->next;
				while(ptr != NULL)
				{
					if ((ptr->router_id.s_addr == dijkstra_popped_item->topology_entry->neighbor_id.s_addr) &&
							(ptr->net_num.s_addr != dijkstra_popped_item->topology_entry->net_num.s_addr) &&
							(ptr->neighbor_id.s_addr != dijkstra_popped_item->topology_entry->neighbor_id.s_addr))
					{
						struct pwospf_topology_entry* clone = clone_pwospf_topology_entry(ptr);

						struct route_dijkstra_node* to_be_pushed = create_dikjstra_item(clone, dijkstra_popped_item->cost + 1);
						to_be_pushed->parent = dijkstra_popped_item;

						// Push a visited node into the stack structure to calculate the dijkstra
						dijkstra_stack_push(dijkstra_heap, to_be_pushed);

						// Change the order of the best node
						struct route_dijkstra_node* node_walker = dijkstra_heap;
						while (node_walker->next != NULL)
						{
							if (node_walker->next->next == NULL)
							{
								break;
							}

							if (node_walker->next->cost > node_walker->next->next->cost)
							{
								struct route_dijkstra_node* temp_walker_1 = node_walker->next->next->next;
								struct route_dijkstra_node* temp_walker_2 = node_walker->next->next;
								node_walker->next->next->next = node_walker->next;
								node_walker->next->next = temp_walker_1;
								node_walker->next = temp_walker_2;
							}
							node_walker = node_walker->next;
						}
					}
					ptr = ptr->next;
				}
			}

			struct route_dijkstra_node* final_item = dijkstra_stack_pop(dijkstra_stack);

			if (final_item != NULL)
			{
				while (final_item->parent != NULL)
				{
					final_item = final_item->parent;

					struct sr_if* next_hop_int = sr->if_list;
					while (next_hop_int != NULL)
					{
						if ((next_hop_int->ip & htonl(0xfffffffe)) == (final_item->topology_entry->next_hop.s_addr & htonl(0xfffffffe)))
						{
							break;
						}

						next_hop_int = next_hop_int->next;
					}

					sr_add_rt_entry(sr, topo_entry->net_num, final_item->topology_entry->next_hop, topo_entry->net_mask, next_hop_int->name, 110);
				}
			}

			topo_entry = topo_entry->next;
		}

		Debug("\n-> PWOSPF: Dijkstra algorithm completed\n\n");
		Debug("\n-> PWOSPF: Printing the forwarding table\n");
		print_routing_table(sr);

		pthread_mutex_unlock(&mutex_lock_dijkstra);

		return NULL;
	}
