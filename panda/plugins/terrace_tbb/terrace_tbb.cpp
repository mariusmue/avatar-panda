#include "qemu/osdep.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <iostream>
#include <fstream>

#include "panda/plugin.h"
#include "tbb.pb.h"


extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

extern int errno;

namespace {
const char * trace_file_name;
TBBBlocks blocks;

target_ulong last_pc = 0; 
unsigned int n = 0;

target_ulong asid;
target_ulong start_addr;
std::ofstream log_file;

}

void write_entry(void) {

    TBBBlock *b = blocks.add_basic_blocks();
    b->set_address(last_pc);
    b->set_n(n);
    n = 1;
}


int before_block_exec_trace_tb(CPUState *env, TranslationBlock *tb) {

    //If after_block_exec is used, the below check will fail after a block from kernel to userspace
    if(panda_in_kernel(env)) return 0;

    target_ulong pc = tb->pc;

    // If the trace begins at a specified breakpoint start_addr,
    // then we can set the ASID for later filtering
    if( start_addr != 0 && pc == start_addr ) {
        asid = panda_current_asid(env);
    }

    // Don't bother logging memory read if performed by process we're not interested in. 
    // Nor if we only want to BBs within a specific memory range.
    //if(!asid || panda_current_asid(env) != asid) return 0;

    // Nasty hack, but for testing, the ARM binary will use two fixed ASIDs
    if( !(panda_current_asid(env) == 0x72a2db0 || panda_current_asid(env) == 0x72a0000)) return 0;

    if ( (pc != last_pc || n == UINT_MAX ) && n > 0) {
        if(log_file.is_open())
            log_file << std::hex << last_pc << "    " << panda_current_asid(env) << "    " << std::dec << n << std::endl;

        write_entry();
    }
    else {
        n++;
    }
    last_pc = pc;
    return 0;
}

bool init_plugin(void *self) {

    panda_arg_list *args = panda_get_args("terrace_tbb");

    trace_file_name = panda_parse_string_opt(args, "trace_file",
            "basic_blocks.bin", "File to store traced BB addresses");
    asid = panda_parse_ulong_opt(args, "asid", 0, 
            "The address space ID for the target process");
    start_addr = panda_parse_ulong_opt(args, "start_addr", 0, "known start/breakpoint address in record");

    const char* log_file_name = panda_parse_string_opt(args, "log_file", "", "Text based logging of basic blocks with their ASID");

    if(strlen(log_file_name) != 0)
        log_file.open(log_file_name, std::ios::out);

    panda_cb pcb;

    pcb.before_block_exec = before_block_exec_trace_tb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    write_entry();
    
    // write blocks to file
    std::ofstream file;

    file.open(trace_file_name, std::ios::out | std::ios::binary);

    if (!file) {
        std::cerr << "Failed to open " << trace_file_name << ":" << strerror(errno) << std::endl;
        exit(1);
    }
    blocks.SerializeToOstream(&file);
    log_file.close();
}