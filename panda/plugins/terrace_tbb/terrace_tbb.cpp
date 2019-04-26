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


static FILE * trace_file = NULL;
static target_ulong last_pc = 0; 
static int n = 0;

typedef struct entry {
    uint32_t n;
    target_ulong pc;
} entry_t;

void write_entry(void)
{
    entry_t e;

    e.pc = last_pc;
    e.n = n;
    if ( fwrite( &e, sizeof(entry_t), 1, trace_file) != 1){
        fprintf(stderr, "Couldn't write pc: %s\n", strerror(errno));
        exit(-1);
    }
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

    const char *trace_file_name = panda_parse_string_opt(args, "trace_file",
            "basic_blocks.bin", "File to store traced BB addresses");

    trace_file = fopen(trace_file_name, "w");
    if(trace_file == NULL) {
        fprintf(stderr, "Cannot open/create trace file: %s\n", strerror(errno));
        return false;
    }

    panda_cb pcb;

    pcb.after_block_exec = after_block_exec_trace_tb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    write_entry();
    fclose(trace_file);
}
