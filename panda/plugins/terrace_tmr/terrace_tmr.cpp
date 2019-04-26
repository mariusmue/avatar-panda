#include "qemu/osdep.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "panda/plugin.h"


extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

extern int errno;


static FILE * mem_dump_file = NULL;
static FILE * smem_trace_file = NULL;


int mem_read_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size){
    return 0;
}

bool init_plugin(void *self) {

    panda_arg_list *args = panda_get_args("terrace_tmr");

    const char *nmem_file_name = panda_parse_string_opt(args, "memory_file",
            "dumped_mem.bin", "File to store memory reads for initialization");
    const char *smem_file_name = panda_parse_string_opt(args, "special_memory_file",
            "special_reads.bin", "File storing special memory read");
    const char *config_file_name = panda_parse_string_opt(args, "config_file",
            "conf.json", "JSON file configuring the memory ranges");

    bool virtual_memory = panda_parse_bool_opt(args, "virt_mem",
            "Log virtual addresses instead of physical");
 

    panda_enable_memcb();

    panda_cb pcb;

    if (virtual_memory == true){
        pcb.virt_mem_after_read = mem_read_cb;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    }
    else {
        pcb.phys_mem_after_read = mem_read_cb;
        panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, pcb);
    }

    return true;
}

void uninit_plugin(void *self) {
}
