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

}

void write_entry(void)
{

    TBBBlock *b = blocks.add_basic_blocks();
    b->set_address(last_pc);
    b->set_n(n);
    n = 1;
}


int after_block_exec_trace_tb(CPUState *env, TranslationBlock *tb) {
    target_ulong pc = tb->pc;

    if ( (pc != last_pc || n == UINT_MAX ) && n > 0) {
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
