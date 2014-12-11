#include "pwospf_protocol.h"
#include "neighber.h"

void add_neighbor(neighbor_list* ngh_head, neighbor_list* new_neighbor)
{
    if (ngh_head->next != NULL)
    {
        new_neighbor->next = first_neighbor->next;
        first_neighbor->next = new_neighbor;
    }
    else
    {
        first_neighbor->next = new_neighbor;
    }
}
