#include <llvm/IR/Metadata.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include "FPSkel.h"

using namespace llvm;

void
FPSkel::getAnalysisUsage(AnalysisUsage &AU) const
{
	AU.setPreservesCFG(); 
}

std::string getFunctionName(Instruction *Inst)
{
    if (CallInst *call = dyn_cast<CallInst>(Inst)) {
        Function *fun = call->getCalledFunction();
        if (fun)
            return fun->getName().str();
        else
            return std::string("indirect");
    }
    return std::string("nope");
}

void
addMData(Instruction &I, unsigned int pc, unsigned int asm_ins)
{
    LLVMContext &ctx = I.getContext();
	SmallVector<Value *, 4> Ops;

	Ops.push_back(MDString::get(ctx, "guest_asm_pc"));
	char sPc[16];
	sprintf(sPc, "0x%05x", pc);
	Ops.push_back(MDString::get(ctx, sPc));

	Ops.push_back(MDString::get(ctx, "asm_ins"));
	char rawins[16];
	sprintf(rawins, "%x", asm_ins);
	Ops.push_back(MDString::get(ctx, rawins));

	auto Node =  MDNode::get(ctx, Ops);
	I.setMetadata("ASM", Node);
}

bool
FPSkel::runOnFunction(Function &F)
{
    ins curr_ins;
    bool activated = false;

    for (auto &B : F) {
        std::vector<std::reference_wrapper<Instruction>> match_insn;
        for (auto &I : B) {
            if (isa<CallInst>(&I)) {
                auto func_name = getFunctionName(&I);
                std::string prefix("helper_panda_insn_exec");
                if (!func_name.compare(0, prefix.size(), prefix)) {
                    activated = true;
                    if (I.getNumOperands() == 2) {
                        curr_ins = queue->front();
                        int pc = -1;
                        if (ConstantInt* CI = dyn_cast<ConstantInt>(I.getOperand(0))) {
                            pc = CI->getSExtValue();
                        }

                        if (curr_ins.first == pc) {
                            addMData(I, curr_ins.first, curr_ins.second);
                            queue->pop_front();
                        } else {
                            activated = false;
                        }

                    }
                }
            }
            if (activated) {
                addMData(I, curr_ins.first, curr_ins.second);
            }
        }
    }

	// return true if CFG has changed.
	return false;
}

char FPSkel::ID = 0;

