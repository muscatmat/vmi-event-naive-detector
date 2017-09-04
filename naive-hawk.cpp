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
#include <time.h>
#include <pthread.h>
#include <Python.h>

#include <libvmi/libvmi.h> 
#include <libvmi/events.h>

#include "naive-queue.h"
#include "naive-event-list.h"
#include "naive-hawk.h"

/////////////////////
// Defines
/////////////////////
#define UNUSED_PARAMETER(expr) (void)(expr);

#define PAUSE_VM 0

// Event Names Contants
#define INTERRUPTED_EVENT 0
#define PROCESS_EVENT 1

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

Queue<int> event_queue;
struct vmi_event_node *vmi_event_head;

//  VM Specific Information (Retrieved from Volatility)
#define TASK_STRUCT_SIZE 0x950

// Result Measurements
#define MONITORING_MODE
#define MEASURE_EVENT_CALLBACK_TIME
//#define ALWAYS_SEND_EVENT

// Result variables
long irrelevant_events_count = 0;
long monitored_events_count = 0;

int main(int argc, char **argv)
{
    clock_t program_time = clock();
    printf("Naive Event Hawk Program Initiated!\n");

    if(argc != 2)
    {
        fprintf(stderr, "Usage: naive-hawk <Guest VM Name> \n");
        printf("Naive Event Hawk-Eye Program Ended!\n");
        return 1; 
    }

    // Initialise variables
    vmi_instance_t vmi;

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

    #ifdef MONITORING_MODE    
    // Start security checking thread
    pthread_t sec_thread;
    if (pthread_create(&sec_thread, NULL, security_checking_thread, NULL) != 0)
        printf("Failed to create thread");
    #endif

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

    // Register Processes Events
    if (register_processes_events(vmi) == false)
    {
        printf("Registering of processes events failed!\n");

        cleanup(vmi);
        printf("Naive Event Hawk-Eye Program Ended!\n");
        return 4;
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
    program_time = clock() - program_time;
    printf("Execution time: %f seconds\n", ((double)program_time)/CLOCKS_PER_SEC);
    return 0;
}

/////////////////////
// Definitions
/////////////////////
event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event) 
{ 
    #ifdef MEASURE_EVENT_CALLBACK_TIME
    clock_t t;
    t = clock();
    #endif

    #ifdef ALWAYS_SEND_EVENT
        monitored_events_count++;
        vmi_clear_event(vmi, event, NULL);

        #ifdef MONITORING_MODE
        event_queue.push(PROCESS_EVENT);
        #endif

        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

        #ifdef MEASURE_EVENT_CALLBACK_TIME
        t = clock() - t;
        printf("mem_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
        #endif

        return VMI_EVENT_RESPONSE_NONE;
    #endif

    // Always clear event on callback
    vmi_clear_event(vmi, event, NULL);

    monitored_events_count++;

    struct event_data *data = (struct event_data *) event->data;
    
    // Check that adddress hit is within monitoring range    
    addr_t event_addr = (event->mem_event.gfn << 12) + event->mem_event.offset;
    addr_t min_addr = data->physical_addr;
    addr_t max_addr = data->physical_addr + data->monitor_size;

    if (event_addr < min_addr || event_addr > max_addr)
    {
        irrelevant_events_count++;

        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // print_event(event);

    #ifdef MONITORING_MODE
    event_queue.push(PROCESS_EVENT);
    #endif

    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

    #ifdef MEASURE_EVENT_CALLBACK_TIME
    t = clock() - t;
    printf("mem_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
    #endif

    return VMI_EVENT_RESPONSE_NONE;
}

void free_event_data(vmi_event_t *event, status_t rc)
{
    struct event_data * data = (struct event_data *) event->data;
    printf("Freeing data for physical address: \%" PRIx64" from page: \%" PRIx64" due to status %d \n", data->physical_addr, data->physical_addr << 12, rc);
    free(data); 
}

bool register_processes_events(vmi_instance_t vmi)
{
    printf("Registering Processes Events\n");

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
        printf("%d\t%s (struct addr: \%" PRIx64")\n", pid, procname, current_process);
        if (procname) 
        {
            free(procname);
            procname = NULL;
        }

        addr_t struct_addr = vmi_translate_kv2p(vmi, current_process);
        printf("Registering event for physical addr: %" PRIx64"\n", struct_addr);
        // Register write memory event (>> 12 to point to page base)
        vmi_event_t *proc_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
        SETUP_MEM_EVENT(proc_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);
        
        // Setup event context data
        struct event_data *event_data = (struct event_data *) malloc(sizeof(struct event_data));
        event_data->physical_addr = struct_addr;
        event_data->monitor_size = TASK_STRUCT_SIZE;

        proc_event->data = event_data;

        if (vmi_register_event(vmi, proc_event) == VMI_FAILURE)
            printf("Failed to register event!\n");
        else
            push_vmi_event(&vmi_event_head, proc_event);

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE)
        {
            printf("Failed to read next pointer in loop at %" PRIx64"\n", next_list_entry);
            return false;
        }
    } while(next_list_entry != list_head);

    return true;
}

void cleanup(vmi_instance_t vmi)
{
    // Send Interrupt event to security checking thread
    event_queue.push(INTERRUPTED_EVENT);

    if(PAUSE_VM == 1) 
        vmi_resume_vm(vmi);

    struct vmi_event_node *current = vmi_event_head;
    struct vmi_event_node *next = vmi_event_head;

    while (current) 
    {
        next = current->next;

        vmi_clear_event(vmi, current->event, free_event_data);

        free(current);
        current = next;
    }

    // Perform cleanup of libvmi instance
    vmi_destroy(vmi);

    // Print Statistics
    if (monitored_events_count != 0) 
    {
        printf("Total Irrelevant Events: %ld\n", irrelevant_events_count);
        printf("Total Hit Events: %ld\n", (monitored_events_count - irrelevant_events_count));
        printf("Total Monitored Events: %ld\n", monitored_events_count);
        printf("Total Irrelevant Events Percentage: %f%%\n", (double) irrelevant_events_count / (double)monitored_events_count * 100);
        printf("Total Hit Events: %f%%\n", (1 - (double) irrelevant_events_count / (double)monitored_events_count) * 100);
    }
}

void print_event(vmi_event_t *event)
{
    printf("PAGE ACCESS: %c%c%c for GFN %" PRIx64" (offset %06" PRIx64") gla %016" PRIx64" (vcpu %" PRIu32")\n",
        (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
        event->mem_event.gfn,
        event->mem_event.offset,
        event->mem_event.gla,
        event->vcpu_id
    );
}

void *security_checking_thread(void *arg)
{
    UNUSED_PARAMETER(arg);
    printf("Security Checking Thread Initated!\n");

    // Py_Initialize();

    // PyRun_SimpleString("import sys\n"
    //                    "sys.path.append('/usr/local/src/volatility-master')\n"
    //                    "import volatility.conf as conf\n"
    //                    "import volatility.registry as registry\n"
    //                    "registry.PluginImporter()\n"
    //                    "config = conf.ConfObject()\n"
    //                    "import volatility.commands as commands\n"
    //                    "import volatility.addrspace as addrspace\n"
    //                    "registry.register_global_options(config, commands.Command)\n"
    //                    "registry.register_global_options(config, addrspace.BaseAddressSpace)\n"
    //                    "config.parse_options()\n"
    //                    "config.PROFILE='LinuxDebian31604x64'\n"
    //                    "config.LOCATION='vmi://debian-hvm'\n"
    //                    "from time import time,ctime\n"
    //                    "print 'Time is',ctime(time())");

    // PyRun_SimpleString("from time import time,ctime\n"
    //                    "print 'Today is',ctime(time())\n");

    int event_type = INTERRUPTED_EVENT;
    while(!interrupted)
    {
        event_type = event_queue.pop();

        if (event_type == INTERRUPTED_EVENT)
        {
            printf("Encountered INTERRUPTED_EVENT\n");
            printf("Security Checking Thread Ended!\n"); 
            // Py_Finalize();
            return NULL;
        }
           
        printf("Encountered PROCESS_EVENT\n");
    }
    
    printf("Security Checking Thread Ended!\n");
    Py_Finalize();
    return NULL;
}