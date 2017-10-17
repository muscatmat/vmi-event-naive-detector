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

#include "naive-deque.h"
#include "naive-event-list.h"
#include "naive-hawk.h"

#include <atomic>

using namespace std;
  
/////////////////////
// Defines
/////////////////////
#define UNUSED_PARAMETER(expr) (void)(expr);

#define PAUSE_VM 0

// Event Names Contants
#define INTERRUPTED_EVENT 0
#define PROCESS_EVENT 1
#define MODULE_EVENT 2
#define AFINFO_EVENT 4

/////////////////////
// Global Variables
/////////////////////

Deque<int> event_deque;
struct vmi_event_node *vmi_event_head;

//  VM Specific Information (Retrieved from Volatility)
#define TASK_STRUCT_SIZE 0x950
#define MODULE_STRUCT_SIZE 0x258
#define TCP_AFINFO_STRUCT_SIZE 0x38
#define UDP_AFINFO_STRUCT_SIZE 0x40

// Result Measurements
#define MONITORING_MODE
#define MEASURE_EVENT_CALLBACK_TIME
#define ALWAYS_SEND_EVENT /* Always send event due to register multiple event on same page failure */
//#define MONITOR_PROCESSES_EVENTS
#define MONITOR_MODULES_EVENTS
//#define MONITOR_AFINFO_EVENTS

// Result variables
long irrelevant_events_count = 0;
long monitored_events_count = 0;

/////////////////////
// Static Functions
/////////////////////
static atomic<bool> interrupted(false);
static void close_handler(int sig)
{
    UNUSED_PARAMETER(sig); 
    interrupted = true;
    event_deque.push_front(INTERRUPTED_EVENT);
}

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

    // FILE *fp;
    // char path[1035];

    // fp = popen("python python-scripts/test.py", "r");
    //     if (fp == NULL) {
    //     printf("Failed to run command\n" );
    //     exit(1);
    // }

    // /* Read the output a line at a time - output it. */
    // while (fgets(path, sizeof(path)-1, fp) != NULL) {
    //     printf("%s", path);
    // }

    // /* close */
    // pclose(fp);

    //system("python python-scripts/test.py");

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
    printf("LibVMI initialise succeeded: \%" PRIx64"\n", vmi);

    #ifdef MONITORING_MODE    
    // Start security checking thread
    pthread_t sec_thread;
    if (pthread_create(&sec_thread, NULL, security_checking_thread, (void *)vmi) != 0)
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
    
    #ifdef MONITOR_PROCESSES_EVENTS
    // Register Processes Events
    if (register_processes_events(vmi) == false)
    {
        printf("Registering of processes events failed!\n");

        cleanup(vmi);
        printf("Naive Event Hawk-Eye Program Ended!\n");
        return 4;
    }
    #endif

    #ifdef MONITOR_MODULES_EVENTS
    // Register Modules Events
    if (register_modules_events(vmi) == false)
    {
        printf("Registering of modules events failed!\n");

        cleanup(vmi);
        printf("Naive Event Hawk-Eye Program Ended!\n");
        return 5;
    }
    #endif

    #ifdef MONITOR_AFINFO_EVENTS
    // Register Afinfo Events
    if (register_afinfo_events(vmi) == false)
    {
        printf("Registering of af info events failed!\n");

        cleanup(vmi);
        printf("Naive Event Hawk-Eye Program Ended!\n");
        return 5;
    }
    #endif

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

        struct event_data *any_data = (struct event_data *) event->data;
        #ifdef MONITORING_MODE
        event_deque.push_back(any_data->type);
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
    event_deque.push_back(data->type);
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
        printf("Registering event for physical addr: %" PRIx64"\n", struct_addr >> 12);
        // Register write memory event (>> 12 to point to page base)
        vmi_event_t *proc_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
        SETUP_MEM_EVENT(proc_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);
        
        // Setup event context data
        struct event_data *event_data = (struct event_data *) malloc(sizeof(struct event_data));
        event_data->type = PROCESS_EVENT;
        event_data->physical_addr = struct_addr;
        event_data->monitor_size = TASK_STRUCT_SIZE;

        proc_event->data = event_data;

        if (vmi_register_event(vmi, proc_event) == VMI_FAILURE)
            printf("Failed to register process event!\n");
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

bool register_modules_events(vmi_instance_t vmi)
{
    printf("Registering Modules Events\n");

    addr_t list_head;
    if (vmi_read_addr_ksym(vmi, "modules", &list_head) == VMI_FAILURE)
    {
        printf("Failed to read modules kernel symbol\n");
        return false;
    } 

    // Perform module list walk-through
    addr_t next_list_entry = list_head;
    char *modname = NULL;
    status_t status;

    printf("\nModule Name\n");
    do 
    {
        if (VMI_PM_IA32E == vmi_get_page_mode(vmi, 0))   // 64-bit paging
            modname = vmi_read_str_va(vmi, next_list_entry + 16, 0);
        else 
            modname = vmi_read_str_va(vmi, next_list_entry + 8, 0);

        if (!modname) 
        {
            printf("Failed to find modname\n");
            return false;
        }

        // Print details
        printf("%s (struct addr: \%" PRIx64")\n", modname, next_list_entry);
        if (modname) 
        {
            free(modname);
            modname = NULL;
        }

        addr_t struct_addr = vmi_translate_kv2p(vmi, next_list_entry);
        printf("Registering event for physical addr: %" PRIx64"\n", struct_addr);
        // Register write memory event (>> 12 to point to page base)
        vmi_event_t *mod_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
        SETUP_MEM_EVENT(mod_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);
        
        // Setup event context data
        struct event_data *event_data = (struct event_data *) malloc(sizeof(struct event_data));
        event_data->type = MODULE_EVENT;
        event_data->physical_addr = struct_addr;
        event_data->monitor_size = MODULE_STRUCT_SIZE;

        mod_event->data = event_data;

        if (vmi_register_event(vmi, mod_event) == VMI_FAILURE)
            printf("Failed to register module event!\n");
        else
            push_vmi_event(&vmi_event_head, mod_event);

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE)
        {
            printf("Failed to read next pointer in loop at %" PRIx64"\n", next_list_entry);
            return false;
        }
    } while(next_list_entry != list_head);

    return true;
}

bool register_afinfo_events(vmi_instance_t vmi){

    printf("Registering Afinfo Events\n");
    char *name = NULL;

    // Register TCP Seq Afinfo Events
    addr_t tcp_seq_afinfo[2];
    if (vmi_read_addr_ksym(vmi, "tcp6_seq_afinfo", &tcp_seq_afinfo[0]) == VMI_FAILURE)
    {
        printf("Failed to read tcp6_seq_afinfo kernel symbol\n");
        return false;
    }

    if (vmi_read_addr_ksym(vmi, "tcp4_seq_afinfo", &tcp_seq_afinfo[1]) == VMI_FAILURE)
    {
        printf("Failed to read tcp4_seq_afinfo kernel symbol\n");
        return false;
    } 

    for (int i = 0; i < 2; i++){
        name = vmi_read_str_va(vmi, tcp_seq_afinfo[i], 0);    
        if (!name) 
        {
            printf("Failed to find name\n");
            return false;
        }

        // Print details
        printf("%s (struct addr: \%" PRIx64")\n", name, tcp_seq_afinfo[i]);
        if (name) 
        {
            free(name);
            name = NULL;
        }

        addr_t struct_addr = vmi_translate_kv2p(vmi, tcp_seq_afinfo[i]);
        printf("Registering event for physical addr: %" PRIx64"\n", struct_addr >> 12);
        // Register write memory event (>> 12 to point to page base)
        vmi_event_t *net_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
        SETUP_MEM_EVENT(net_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);
        
        // Setup event context data
        struct event_data *event_data = (struct event_data *) malloc(sizeof(struct event_data));
        event_data->type = AFINFO_EVENT;
        event_data->physical_addr = struct_addr;
        event_data->monitor_size = TCP_AFINFO_STRUCT_SIZE;

        net_event->data = event_data;

        if (vmi_register_event(vmi, net_event) == VMI_FAILURE)
            printf("Failed to register afinfo event!\n");
        else
            push_vmi_event(&vmi_event_head, net_event);
    }

    // Register UDP Seq Afinfo Events
    addr_t udp_seq_afinfo[4];
    if (vmi_read_addr_ksym(vmi, "udplite6_seq_afinfo", &udp_seq_afinfo[0]) == VMI_FAILURE)
    {
        printf("Failed to read udplite6_seq_afinfo kernel symbol\n");
        return false;
    }

    if (vmi_read_addr_ksym(vmi, "udp6_seq_afinfo", &udp_seq_afinfo[1]) == VMI_FAILURE)
    {
        printf("Failed to read udp6_seq_afinfo kernel symbol\n");
        return false;
    } 

    if (vmi_read_addr_ksym(vmi, "udplite4_seq_afinfo", &udp_seq_afinfo[2]) == VMI_FAILURE)
    {
        printf("Failed to read udplite4_seq_afinfo kernel symbol\n");
        return false;
    }

    if (vmi_read_addr_ksym(vmi, "udp4_seq_afinfo", &udp_seq_afinfo[3]) == VMI_FAILURE)
    {
        printf("Failed to read udp4_seq_afinfo kernel symbol\n");
        return false;
    } 

    for (int i = 0; i < 4; i++){
        name = vmi_read_str_va(vmi, udp_seq_afinfo[i], 0);    
        if (!name) 
        {
            printf("Failed to find name\n");
            return false;
        }

        // Print details
        printf("%s (struct addr: \%" PRIx64")\n", name, udp_seq_afinfo[i]);
        if (name) 
        {
            free(name);
            name = NULL;
        }

        addr_t struct_addr = vmi_translate_kv2p(vmi, udp_seq_afinfo[i]);
        printf("Registering event for physical addr: %" PRIx64"\n", struct_addr >> 12);
        // Register write memory event (>> 12 to point to page base)
        vmi_event_t *net_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
        SETUP_MEM_EVENT(net_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);
        
        // Setup event context data
        struct event_data *event_data = (struct event_data *) malloc(sizeof(struct event_data));
        event_data->type = AFINFO_EVENT;
        event_data->physical_addr = struct_addr;
        event_data->monitor_size = UDP_AFINFO_STRUCT_SIZE;

        net_event->data = event_data;

        if (vmi_register_event(vmi, net_event) == VMI_FAILURE)
            printf("Failed to register afinfo event!\n");
        else
            push_vmi_event(&vmi_event_head, net_event);
    }

    return true;
}

void cleanup(vmi_instance_t vmi)
{
    // Send Interrupt event to security checking thread
    interrupted = true;
    event_deque.push_front(INTERRUPTED_EVENT);

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
    vmi_instance_t vmi = (vmi_instance_t)arg;
    printf("Security Checking Thread Initated:\%" PRIx64"\n", vmi);

    // Py_Initialize();
    // PyRun_SimpleString("from time import time,ctime\n"
    //                    "print 'Today is',ctime(time())\n");
    int res;
    int event_type = INTERRUPTED_EVENT;
    while(!interrupted)
    {
        event_type = event_deque.pop();

        switch (event_type)
        {
            case PROCESS_EVENT:{
                printf("Encountered PROCESS_EVENT\n");
                // Recheck processes
                register_processes_events(vmi);

                // Volatility Plugin linux_check_fop
                res = system("python scripts/check_fop.py");
                // Volatility Plugin linux_check_creds
                res = system("python scripts/check_creds.py");
                break;
            } 
            case MODULE_EVENT:{
                printf("Encountered MODULE_EVENT\n");
                // Recheck modules 
                register_modules_events(vmi);

                // Volatility Plugin linux_check_modules
                res = system("python scripts/check_hidden_modules.py");
                break;
            } 
            case AFINFO_EVENT:
            {
                printf("Encountered AFINFO_EVENT\n");
                // Volatility Plugin linux_check_afinfo
                res = system("python scripts/check_afinfo.py");
                break;
            } 
            case INTERRUPTED_EVENT:
            {
                printf("Encountered INTERRUPTED_EVENT\n");
                printf("Security Checking Thread Ended!\n"); 
                // Py_Finalize();
                return NULL;
            }
            default:
            {
                printf("Unkown event encountered\n");
                printf("Security Checking Thread Ended!\n"); 
                // Py_Finalize();
                return NULL;
            }
        }
    }
    
    printf("Security Checking Thread Ended!\n");
    // Py_Finalize();
    return NULL;
}