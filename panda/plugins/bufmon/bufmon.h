#ifndef _BUFMON_H_
#define _BUFMON_H_

#include "callstack_instr/prog_point.h"
#include "callstack_instr/callstack_instr_ext.h"

typedef void (* on_call_t)(CPUState *env, target_ulong func);
typedef void (* on_ret_t)(CPUState *env, target_ulong func);

#endif
