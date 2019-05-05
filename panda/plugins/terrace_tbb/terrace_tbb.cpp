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
target_ulong end_addr;

}

void write_entry(void) {

    TBBBlock *b = blocks.add_basic_blocks();
    b->set_address(last_pc);
    b->set_n(n);
    n = 1;
}


int after_block_exec_trace_tb(CPUState *env, TranslationBlock *tb) {

    if( !asid || panda_current_asid(env) == asid ) {
        if( !end_addr || ((tb->pc) < end_addr && (tb->pc) >= start_addr) ) {
            target_ulong pc = tb->pc;

            if ( (pc != last_pc || n == UINT_MAX ) && n > 0) {
                write_entry();
            }
            else {
                n++;
            }
            last_pc = pc;
        }
    }
    return 0;
}

bool init_plugin(void *self) {

    panda_arg_list *args = panda_get_args("terrace_tbb");

    trace_file_name = panda_parse_string_opt(args, "trace_file",
            "basic_blocks.bin", "File to store traced BB addresses");
    asid = panda_parse_ulong_opt(args, "asid", 0, 
            "The address space ID for the target process");

    start_addr = panda_parse_ulong_opt(args, "start_addr", 0, "base address of target binary");
    uint32_t size_dec = panda_parse_uint32_opt(args, "bin_size", 0, "address space size (decimal)");
    
    if( size_dec ) end_addr = start_addr + size_dec;
 
    panda_cb pcb;

    pcb.after_block_exec = after_block_exec_trace_tb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

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
}
