#ifndef NAIVE_LIST
#define NAIVE_LIST

#include <libvmi/libvmi.h> 
#include <libvmi/events.h>

struct vmi_event_node {
    vmi_event_t *event;
    struct vmi_event_node *next;
};

void push_vmi_event(struct vmi_event_node **head, vmi_event_t *event) 
{
    struct vmi_event_node *new_node;
    new_node = (struct vmi_event_node *) malloc(sizeof(struct vmi_event_node));

    new_node->event = event;
    new_node->next = *head;
    *head = new_node;
}

vmi_event_t* pop_vmi_event(struct vmi_event_node **head) 
{
    vmi_event_t* retval = NULL;
    struct vmi_event_node *next_node = NULL;

    if (*head == NULL)
        return NULL;

    next_node = (*head)->next;
    retval = (*head)->event;
    free(*head);
    *head = next_node;

    return retval;
}

#endif