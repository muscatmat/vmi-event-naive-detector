/**
 * VMI Event Based Naive Approach Application
 **/
/////////////////////
// Includes
/////////////////////
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>

#include <libvmi/libvmi.h> 
#include <libvmi/events.h>

#include "naive-hawk.h"

/////////////////////
// Defines
/////////////////////
#define PAUSE_VM 0
#define MONITOR_ALL 0
#define MONITOR_NAME 0
#define MONITOR_STATE 1
#define MONITOR_NEXT_TASK 1

//  VM Specific Offsets (Retrieved from Volatility)
#define NAME_OFFSET 0x4F0
#define STATE_OFFSET 0x0
#define TASK_STRUCT_SIZE 0x950

#define TASK_DEAD 64 

/////////////////////
// Static Functions
/////////////////////
static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

/////////////////////
// Global Variables
/////////////////////

vmi_event_t *proc_event;
unsigned long name_offset;
unsigned long pid_offset;
unsigned long tasks_offset;

int main(int argc, char **argv)
{
    printf("Naive Event Hawk Program Initiated!\n");

    if(argc < 2)
    {
        fprintf(stderr, "Usage: naive-hawk <Guest VM Name> <process-name (if applicable)> \n");
        return 1; 
    }

    // Initialise variables
    vmi_instance_t vmi;
    addr_t struct_addr;
    struct event_data *event_data = (struct event_data *) malloc(sizeof(struct event_data));

    proc_event = NULL;

    // Setup signal action handling
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    char *vm_name = argv[1];
    
    // Initialize the libvmi library.
    if (VMI_FAILURE ==
        vmi_init_complete(&vmi, vm_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL))
    {
        printf("Failed to init LibVMI library.\n");
        return 2;
    }
    printf("LibVMI initialise succeeded!\n");

    if(PAUSE_VM == 1) 
    {
        // Pause vm for consistent memory access
        if (VMI_SUCCESS != vmi_pause_vm(vmi))
        {
            printf("Failed to pause VM\n");
            cleanup(vmi);
            return 3;
        }
    }

    // Retrieve process information
    name_offset = vmi_get_offset(vmi, "linux_name");
    pid_offset = vmi_get_offset(vmi, "linux_pid");
    tasks_offset = vmi_get_offset(vmi, "linux_tasks");

    if (argc == 2)
    {
        list_processes(vmi);
        cleanup(vmi);

        printf("Naive Event Hawk-Eye Program Ended!\n");
        return 0;
    }
    
    struct_addr = retrieve_process_info(vmi, argv[2]);
    if (struct_addr == 0)
    {
        printf("Process not found!\n");

        cleanup(vmi);
        printf("Naive Event Hawk-Eye Program Ended!\n");
        return 4;
    }

    printf("Registering event for pysical addr: %"PRIx64"\n", struct_addr);
    // Register write memory event (>> 12 to point to page base)
    proc_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
    SETUP_MEM_EVENT(proc_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);
    
    // Setup event context data
    event_data->physical_addr = struct_addr;
    event_data->monitor_size = TASK_STRUCT_SIZE;
    vmi_read_64_pa(vmi, struct_addr + STATE_OFFSET, &(event_data->process_state));
    printf("Initial Process State: %lu\n", event_data->process_state);

    vmi_read_64_pa(vmi, struct_addr + tasks_offset, &(event_data->next_process));
    printf("Initial Next Process (struct addr: \%"PRIx64")\n", event_data->next_process - tasks_offset);

    if (event_data->next_process == vmi_translate_ksym2v(vmi, "init_task") + tasks_offset)
        printf("Task monitoring next process is init_task\n"); 

    proc_event->data = event_data;

    if (vmi_register_event(vmi, proc_event) == VMI_FAILURE)
    {
        printf("Failed to register event.\n");

        cleanup(vmi);
        printf("Naive Event Hawk-Eye Program Ended!\n");
        return 5;
    }

    printf("Waiting for events...\n");
    while (!interrupted)
    {
         if (vmi_events_listen(vmi, 500) != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

    cleanup(vmi);

    printf("Naive Event Hawk-Eye Program Ended!\n");
    return 0;
}

/////////////////////
// Definitions
/////////////////////

event_response_t state_change_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    if (vmi_register_event(vmi, proc_event) == VMI_FAILURE)
    {
        printf("Failed to register event in callback.\n");

        interrupted = -1;
        return VMI_EVENT_RESPONSE_NONE;
    }

    struct event_data *data = (struct event_data *) event->data;

    uint64_t state;
    vmi_read_64_pa(vmi, data->physical_addr + STATE_OFFSET, &state);

    if (state == data->process_state)
        return VMI_EVENT_RESPONSE_NONE;

    printf("New state of process is: %lu\n", state);
    data->process_state = state;

    if ((state & TASK_DEAD) != 0)
    {
        printf("Process is dead - Ending monitoring\n");

        interrupted = -1;
        return VMI_EVENT_RESPONSE_NONE;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t next_task_change_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    if (vmi_register_event(vmi, proc_event) == VMI_FAILURE)
    {
        printf("Failed to register event in callback.\n");

        interrupted = -1;
        return VMI_EVENT_RESPONSE_NONE;
    }

    struct event_data *data = (struct event_data *) event->data;

    addr_t next_task;
    vmi_read_64_pa(vmi, data->physical_addr + tasks_offset, &next_task);

    if (next_task == data->next_process)
        return VMI_EVENT_RESPONSE_NONE;

    printf("New Task Struct: \%"PRIx64"\n", next_task - tasks_offset);
    data->next_process = next_task;

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t name_change_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    if (vmi_register_event(vmi, proc_event) == VMI_FAILURE)
    {
        printf("Failed to register event in callback.\n");

        interrupted = -1;
        return VMI_EVENT_RESPONSE_NONE;
    }

    struct event_data *data = (struct event_data *) event->data;

    char *procname = vmi_read_str_pa(vmi, data->physical_addr + NAME_OFFSET);
    if (procname) 
    {
        printf("New process Name: %s\n", procname);
        free(procname);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event) 
{ 
    // Always clear event on callback
    vmi_clear_event(vmi, event, NULL);

    struct event_data *data = (struct event_data *) event->data;
    
    // Check that adddress hit is within monitoring range    
    addr_t event_addr = (event->mem_event.gfn << 12) + event->mem_event.offset;
    if (MONITOR_ALL == 1)
    {
        addr_t min_addr = data->physical_addr;
        addr_t max_addr = data->physical_addr + data->monitor_size;

        if (event_addr < min_addr && event_addr > max_addr)
        {
            //printf("\nEvent Address: \%"PRIx64" out of monitoring range", event_addr);
            vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
            return VMI_EVENT_RESPONSE_NONE;
        }
    }
    else
    {
        if (MONITOR_STATE == 1 && event_addr == (data->physical_addr + STATE_OFFSET))
        {
            vmi_step_event(vmi, event, event->vcpu_id, 1, state_change_callback);
            return VMI_EVENT_RESPONSE_NONE;
        }

        if (MONITOR_NEXT_TASK == 1 && event_addr == (data->physical_addr + tasks_offset))
        {
            vmi_step_event(vmi, event, event->vcpu_id, 1, next_task_change_callback);
            return VMI_EVENT_RESPONSE_NONE;
        }

        if (MONITOR_NAME == 1 && event_addr == (data->physical_addr + NAME_OFFSET))
        {
            vmi_step_event(vmi, event, event->vcpu_id, 1, name_change_callback);
            return VMI_EVENT_RESPONSE_NONE;
        }

        //printf("\nEvent Address: \%"PRIx64" out of monitoring range\n", event_addr);
        
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        return VMI_EVENT_RESPONSE_NONE;
    }
    
    print_event(event);

    printf("\nEvent Address: \%"PRIx64" Min Addr: \%"PRIx64" Max Addr: \%"PRIx64"\n", 
    (event->mem_event.gfn << 12) + event->mem_event.offset, data->physical_addr, data->physical_addr + data->monitor_size);

    uint64_t state;
    vmi_read_64_pa(vmi, data->physical_addr + STATE_OFFSET, &state);

    char *procname = vmi_read_str_pa(vmi, data->physical_addr + NAME_OFFSET);
    if (procname) 
    {
        printf("Process Name: %s\n", procname);
        free(procname);
    }
    
    printf("State of process is: \%"PRIx64"\n", state);

    // Based on what has changed call different callback and read what has changed
    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
    return VMI_EVENT_RESPONSE_NONE;
}

void free_event_data(vmi_event_t *event, status_t rc)
{
    struct event_data * data = (struct event_data *) event->data;
    printf("Freeing data for physical address: \%"PRIx64" due to status %d \n", data->physical_addr, rc);
    free(data); 
}

addr_t retrieve_process_info(vmi_instance_t vmi, char *req_process) 
{
    printf("Searching for process: %s\n", req_process);
    
    unsigned long tasks_offset = vmi_get_offset(vmi, "linux_tasks");

    addr_t list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;

    addr_t next_list_entry = list_head;

    // Perform task list walk-through
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    status_t status;

    do 
    {
        current_process = next_list_entry - tasks_offset;

        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
        if (!procname) 
        {
            printf("Failed to find procname\n");
            return 0;
        }

        if (procname && strcmp(procname, req_process) == 0){
            printf("Found Process with PID: %d and struct addr: \%"PRIx64"\n", pid, current_process);
            free(procname);
            return vmi_translate_kv2p(vmi, current_process);
        }
        
        if (procname) 
        {
            free(procname);
            procname = NULL;
        }

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) 
        {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            return 0;
        }
    } while(next_list_entry != list_head);

    return 0;
}

bool list_processes(vmi_instance_t vmi)
{
    printf("Listing Processes\n");

    unsigned long tasks_offset = vmi_get_offset(vmi, "linux_tasks");
    unsigned long name_offset = vmi_get_offset(vmi, "linux_name");
    unsigned long pid_offset = vmi_get_offset(vmi, "linux_pid");

    addr_t list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;

    addr_t next_list_entry = list_head;

    // Perform task list walk-through
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    status_t status;

    printf("\nPID\tProcess Name\n");
    do 
    {
        current_process = next_list_entry - tasks_offset;

        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
        if (!procname) 
        {
            printf("Failed to find procname\n");
            return false;
        }

        // Print details
        printf("%d\t%s (struct addr: \%"PRIx64")\n", pid, procname, current_process);
        if (procname) 
        {
            free(procname);
            procname = NULL;
        }

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE)
         {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            return false;
        }
    } while(next_list_entry != list_head);

    return true;
}

void cleanup(vmi_instance_t vmi)
{
    if(PAUSE_VM == 1) 
        vmi_resume_vm(vmi);

    if (proc_event != NULL)
        vmi_clear_event(vmi, proc_event, free_event_data);

    // Perform cleanup of libvmi instance
    vmi_destroy(vmi);

    free(proc_event);
}

void print_event(vmi_event_t *event)
{
    printf("PAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %"PRIu32")\n",
        (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
        event->mem_event.gfn,
        event->mem_event.offset,
        event->mem_event.gla,
        event->vcpu_id
    );
}