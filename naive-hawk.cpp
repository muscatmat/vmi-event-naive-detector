/**
 * VMI Event Based Naive Approach Application
 **/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>

#include <libvmi/libvmi.h> 
#include <libvmi/events.h>

#include "naive-hawk.h"

static int interrupted = 0;
static void close_handler(int sig){
    interrupted = sig;
}

int main(int argc, char **argv)
{
    printf("Naive Event Hawk Program Initiated!\n");

    if(argc != 2){
        fprintf(stderr, "Usage: naive-hawk <Guest VM Name>\n");
        return 1; 
    }

    // Init variables
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

    // Pause vm for consistent memory access
    if (VMI_SUCCESS != vmi_pause_vm(vmi)) {
        printf("Failed to pause VM\n");
        cleanup(vmi);
        return 3;
    }

    // Modes: Identification (m) / Monitoring (m)
    // e.g <MODE> <STRUCT_TYPE> <STRUCT_OFFSET> <FIELD_NAME>
   char ch;
   char mode;
   char struct_type[100];
   unsigned int addr_offset;
   char struct_member[100];

   do
   {
        printf("\nEnter VMI Information request in format: <MODE> <STRUCT_TYPE> <STRUCT_OFFSET> <FIELD_NAME>\n");
        int input_length = scanf("%c %s %x %s", &mode, struct_type, &addr_offset, struct_member);
        if (input_length != 4)
            break;

        // MM - Supported struct types: PROCESS
        if (strcmp(struct_type, "PROCESS") == 0){
            // General case
            if (list_processes(vmi) == false)
                break;

            // MM - TODO: Compare offsets and field names for identification
            continue;
        }

        printf("Information entered: %c %s 0x%x %s\n", mode, struct_type, addr_offset, struct_member);
    } while ((ch = getchar()) != EOF || ch != '\n' || !interrupted);

    cleanup(vmi);

    printf("\nNaive Event Hawk-Eye Program Ended!\n");
    return 0;
}

bool list_processes(vmi_instance_t vmi){
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
    do {
        current_process = next_list_entry - tasks_offset;

        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
        if (!procname) {
            printf("Failed to find procname\n");
            return false;
        }

        // Print details
        printf("%d\t%s (struct addr: \%"PRIx64")\n", pid, procname, current_process);
        if (procname) {
            free(procname);
            procname = NULL;
        }

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            return false;
        }
    } while(next_list_entry != list_head);

    return true;
}

void cleanup(vmi_instance_t vmi)
{
    vmi_resume_vm(vmi);

    // Perform cleanup of libvmi instance
    vmi_destroy(vmi);
}