#ifndef	__FPSKEL_H
#define	__FPSKEL_H

#include <llvm/Pass.h>

#include <deque>
#include <utility>

typedef std::pair<unsigned long, unsigned int> ins;

namespace llvm {

struct FPSkel : public FunctionPass {

	/*
	 * For all of your passes you will need this and to define it.
	 * It's address is used by pass system, so the value does not matter.
	 */
	static char ID;

	FPSkel(std::deque<ins>* queue) : FunctionPass(ID), queue(queue) { }

	// Called on each function in given compilation unit 
	virtual bool runOnFunction(Function &);

	/*
	 * Used to help order passes by pass manager.
	 * Declare any passes you need run prior here.. as well as
	 * any information such as preserving CFG or similar. 
	 */
	virtual void getAnalysisUsage(AnalysisUsage &) const;

	// WARN: pointer to global inside PANDA plugin
	private:
		std::deque<ins>* queue;

};

}

#endif
