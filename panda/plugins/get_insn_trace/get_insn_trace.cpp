#include "panda/plugin.h"
#if defined(TARGET_ARM)

#include <stdlib.h>
#include "panda/plog-cc.hpp"

extern "C" {
bool init_plugin(void *self);
void uninit_plugin(void *self);
}

extern PandaLog globalLog;

int bb_insn_count = 0;
int byte_count = 0;
int fd;


int before_block_exec(CPUState *cpu, TranslationBlock *tb){
    static uint64_t bb_count = 0;
    int ret;
    uint8_t *code;
    bb_insn_count = 0;

    printf("===========before_block_exec - size: %x, icount: %x, pc: %x ============\n", tb->size, tb->icount, tb->pc);

    fprintf(stderr, "===========before_block_exec - size: %x, icount: %x, pc: %x ============\n", tb->size, tb->icount, tb->pc);

    // allocate space for the content of the basic block
    code = (uint8_t *) calloc (tb->size + 1, sizeof(uint8_t));

    ret = panda_virtual_memory_read(cpu, tb->pc, code, tb->size);
    if (ret != 0 ){
        fprintf(stderr, "panda_virtual_memory_read() failed\n");
        perror("");
        return -1;
    }

    fprintf(stderr, "code: ");
    for (int i = 0; i < tb->size; i++) {
        fprintf(stderr, "%x ", code[i]);
    }
    ret = write(fd, code, tb->size);
    if (ret != tb->size) {
        fprintf(stderr, "read() failed\n");
        perror("");
        return -1;
    }
    byte_count += ret;
    fprintf(stderr, "\n");

    // write basic block to pandalog
    if (pandalog) {
        std::unique_ptr<panda::LogEntry> ple(new panda::LogEntry());
        ple->mutable_basicblockentry()->set_bb_number(bb_count);
        ple->mutable_basicblockentry()->set_address(tb->pc);
        ple->mutable_basicblockentry()->set_size(tb->size);
        ple->mutable_basicblockentry()->set_icount(tb->icount);
        ple->mutable_basicblockentry()->set_content((char *) code, tb->size);
        globalLog.write_entry(std::move(ple));
    }
    bb_count++;

    return 0;
}

bool insn_translate(CPUState *cpu, target_ulong pc){
    return true;
}

int insn_exec(CPUState *cpu, target_ulong pc){
    printf("\t\t%x. cpu->panda_guest_pc: %lx\n", bb_insn_count, cpu->panda_guest_pc);
    bb_insn_count++;

    return 0;
}


bool init_plugin(void *self){
    printf("[get_insn_trace] init_plugin\n");

    panda_cb pcb;     

    panda_enable_precise_pc();

    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.insn_translate = insn_translate;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = insn_exec;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    fd = open("/tmp/tmpfile", O_WRONLY | O_CREAT | O_TRUNC, 0744);

    return true;
}


void uninit_plugin(void *self){
    printf("[get_insn_trace] uninit_plugin\n");
    fprintf(stderr, "total written bytes: %x (%d)\n", byte_count, byte_count);
    if (pandalog){
        printf("pandalog\n");
    }
}


#endif // TAGET_ARM
