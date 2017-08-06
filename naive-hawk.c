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
        vmi_init(&vmi, VMI_XEN, (void*)vm_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL, NULL))
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
        printf("Enter VMI Information request in format: <MODE> <STRUCT_TYPE> <STRUCT_OFFSET> <FIELD_NAME>\n");
        int input_length = scanf("%c %s %x %s", &mode, struct_type, &addr_offset, struct_member);
        if (input_length != 4)
            break;

        // MM - TODO: RETRIVE DATA

        // PRINT DATA

        printf("Information entered: %c %s 0x%x %s\n", mode, struct_type, addr_offset, struct_member);
    } while ((ch = getchar()) != EOF || ch != '\n' || !interrupted);

    cleanup(vmi);

    printf("\nNaive Event Hawk-Eye Program Ended!\n");
    return 0;
}

void cleanup(vmi_instance_t vmi)
{
    vmi_resume_vm(vmi);

    // Perform cleanup of libvmi instance
    vmi_destroy(vmi);
}