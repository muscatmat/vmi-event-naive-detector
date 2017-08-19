#ifndef NAIVE_HAWK
#define NAIVE_HAWK

/////////////////////
// Structs
/////////////////////

struct event_data 
{
    // Physical address of event to monitor
    long physical_addr;

    // Size of monitoring page
    long monitor_size;

    // Monitoring information
    unsigned long process_state;

};

///////////////////// 
// Functions
/////////////////////

void cleanup(vmi_instance_t vmi);

event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event);
event_response_t state_change_callback(vmi_instance_t vmi, vmi_event_t *event);
event_response_t name_change_callback(vmi_instance_t vmi, vmi_event_t *event);

void free_event_data(vmi_event_t *event, status_t rc);
void print_event(vmi_event_t *event);

addr_t retrieve_process_info(vmi_instance_t vmi, char *req_process);
bool list_processes(vmi_instance_t vmi);

#endif