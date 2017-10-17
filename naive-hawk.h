#ifndef NAIVE_HAWK
#define NAIVE_HAWK

/////////////////////
// Structs
/////////////////////

struct event_data 
{
    // Event type
    unsigned long type;

    // Physical address of event to monitor
    unsigned long physical_addr;

    // Size of monitoring page
    unsigned long monitor_size;
};

///////////////////// 
// Functions
/////////////////////

void cleanup(vmi_instance_t vmi);

event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event);

void free_event_data(vmi_event_t *event, status_t rc);
void print_event(vmi_event_t *event);

bool register_processes_events(vmi_instance_t vmi);
bool register_modules_events(vmi_instance_t vmi);
bool register_afinfo_events(vmi_instance_t vmi);

void *security_checking_thread(void *arg);

#endif