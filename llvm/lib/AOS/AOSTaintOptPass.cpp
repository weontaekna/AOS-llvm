#include "llvm/Transforms/Scalar.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/Pass.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/AOS/AOS.h"
#include <iostream>

using namespace llvm;
using namespace AOS;

#define DEBUG_TYPE "aos_taint_opt_pass"

STATISTIC(StatTaintSignDataPointer, "Number of data pointers signed");
STATISTIC(StatTaintStripDataPointer, "Number of data pointers stripped");

namespace {
  class AOSTaintOptPass : public BasicBlockPass {

  public:
    static char ID; // Pass identification, replacement for typeid
    AOSTaintOptPass() : BasicBlockPass(ID) {}

    bool runOnBasicBlock(BasicBlock &BB) override;

  private:  
    bool handleMalloc(Function *pF, CallInst *pCI);
    bool handleCalloc(Function *pF, CallInst *pCI);
    bool handleRealloc(Function *pF, CallInst *pCI);
    bool handleFree(Function *pF, CallInst *pCI);
		bool doReachTainted(Value *pV);
  };
}

char AOSTaintOptPass::ID = 0;
static RegisterPass<AOSTaintOptPass> X("aos-taint", "AOS taint opt pass");

Pass *llvm::AOS::createAOSTaintOptPass() { return new AOSTaintOptPass(); }

bool AOSTaintOptPass::runOnBasicBlock(BasicBlock &BB) {
  bool basicblock_modified = false;

  std::list<CallInst*> callInsts;

  for (auto &I : BB) {
    if (CallInst *CI = dyn_cast<CallInst>(&I)) {
      Function *pF = CI->getCalledFunction();

      if (pF && pF->getName() == "malloc") {
        //callInsts.push_back(CI);
        basicblock_modified = handleMalloc(pF, CI) || basicblock_modified;
      } else if (pF && pF->getName() == "calloc") {
        //callInsts.push_back(CI);
        basicblock_modified = handleCalloc(pF, CI) || basicblock_modified;
      } else if (pF && pF->getName() == "realloc") {
        //callInsts.push_back(CI);
        basicblock_modified = handleRealloc(pF, CI) || basicblock_modified;     
      } else if (pF && pF->getName() == "free") {
        //callInsts.push_back(CI);
        basicblock_modified = handleFree(pF, CI) || basicblock_modified;
      } else if (pF && pF->getName() == "_Znwm") { // new
        //callInsts.push_back(CI);
        basicblock_modified = handleMalloc(pF, CI) || basicblock_modified;
      } else if (pF && pF->getName() == "_Znam") { // new[]
        //callInsts.push_back(CI);
        basicblock_modified = handleMalloc(pF, CI) || basicblock_modified;
      } else if (pF && pF->getName() == "_ZdlPv") { //delete
        //callInsts.push_back(CI);
        basicblock_modified = handleFree(pF, CI) || basicblock_modified;
      } else if (pF && pF->getName() == "_ZdaPv") { // delete[]
        //callInsts.push_back(CI);
        basicblock_modified = handleFree(pF, CI) || basicblock_modified;
      }
    }
  }

  //while (!callInsts.empty()) {
  //  CallInst *CI = callInsts.front();
  //  CI->eraseFromParent();
  //  callInsts.pop_front();
  //}

  return basicblock_modified;
}

bool AOSTaintOptPass::handleMalloc(Function *pF, CallInst *pCI) {
	if (!doReachTainted(dyn_cast<Value>(pCI)))
		return false;

  Value* arg = pCI->getArgOperand(0);
  Value* args[] = {arg};

  //args[0]->dump();
  //std::cout << args[0]->getType();
  //args[0]->mutateType(Type::getInt32Ty(C));
  //args[0]->dump();
  //std::cout << args[0]->getType();

  LLVMContext &C = pF->getContext();
  std::vector<Type*> paramTypes = {Type::getInt64Ty(C)};
  Type *retType = Type::getInt8PtrTy(C);
  FunctionType *FuncType = FunctionType::get(retType, paramTypes, false);
  //Constant *malloc = pF->getParent()->getOrInsertFunction("aos_malloc", FuncType);
  Constant *malloc = pF->getParent()->getOrInsertFunction("_Z10aos_mallocm", FuncType);

  IRBuilder<> Builder(pCI->getNextNode());

  auto newCI = Builder.CreateCall(malloc, args);

  pCI->replaceAllUsesWith(newCI);

  if (pCI->isTailCall())
    newCI->setTailCall();

  StatTaintSignDataPointer++;

  return true;
}

bool AOSTaintOptPass::handleCalloc(Function *pF, CallInst *pCI) {
	if (!doReachTainted(dyn_cast<Value>(pCI)))
		return false;

  auto arg0 = pCI->getArgOperand(0);
  auto arg1 = pCI->getArgOperand(1);
  Value* args[] = {arg0, arg1};

  LLVMContext &C = pF->getContext();
  std::vector<Type*> paramTypes = {Type::getInt64Ty(C), Type::getInt64Ty(C)};
  Type *retType = Type::getInt8PtrTy(C);
  FunctionType *FuncType = FunctionType::get(retType, paramTypes, false);
  //Constant *calloc = pF->getParent()->getOrInsertFunction("aos_calloc", FuncType);
  Constant *calloc = pF->getParent()->getOrInsertFunction("_Z10aos_callocmm", FuncType);

  IRBuilder<> Builder(pCI->getNextNode());

  auto newCI = Builder.CreateCall(calloc, args);

  pCI->replaceAllUsesWith(newCI);

  if (pCI->isTailCall())
    newCI->setTailCall();

  StatTaintSignDataPointer++;

  return true;
}

bool AOSTaintOptPass::handleRealloc(Function *pF, CallInst *pCI) {
	if (!doReachTainted(dyn_cast<Value>(pCI)))
		return false;

  auto arg0 = pCI->getArgOperand(0);
  auto arg1 = pCI->getArgOperand(1);
  Value* args[] = {arg0, arg1};

  LLVMContext &C = pF->getContext();
  std::vector<Type*> paramTypes = {Type::getInt8PtrTy(C), Type::getInt64Ty(C)};
  Type *retType = Type::getInt8PtrTy(C);
  FunctionType *FuncType = FunctionType::get(retType, paramTypes, false);
  //Constant *realloc = pF->getParent()->getOrInsertFunction("aos_realloc", FuncType);
  Constant *realloc = pF->getParent()->getOrInsertFunction("_Z11aos_reallocPvm", FuncType);

  IRBuilder<> Builder(pCI->getNextNode());

  auto newCI = Builder.CreateCall(realloc, args);

  pCI->replaceAllUsesWith(newCI);

  if (pCI->isTailCall())
    newCI->setTailCall();

  StatTaintSignDataPointer++;

  return true;
}

bool AOSTaintOptPass::handleFree(Function *pF, CallInst *pCI) {
	if (!doReachTainted(dyn_cast<Value>(pCI)))
		return false;

  auto arg = pCI->getArgOperand(0);
  Value* args[] = {arg};

  LLVMContext &C = pF->getContext();
  std::vector<Type*> paramTypes = {Type::getInt8PtrTy(C)};
  Type *retType = Type::getVoidTy(C);
  FunctionType *FuncType = FunctionType::get(retType, paramTypes, false);
  //Constant *free = pF->getParent()->getOrInsertFunction("aos_free", FuncType);
  Constant *free = pF->getParent()->getOrInsertFunction("_Z8aos_freePv", FuncType);

  IRBuilder<> Builder(pCI->getNextNode());

  auto newCI = Builder.CreateCall(free, args);

  pCI->replaceAllUsesWith(newCI);

  if (pCI->isTailCall())
    newCI->setTailCall();

  StatTaintStripDataPointer++;

  return true;
}

bool AOSTaintOptPass::doReachTainted(Value *pV) {

	//errs() << "Check doReachTainted\n";

	if (auto Inst = dyn_cast<Instruction>(pV))
		if (Inst->isTainted())
			return true;

  for (auto U : pV->users()) {
    if (auto Inst = dyn_cast<Instruction>(U)) {

			if (Inst == dyn_cast<Instruction>(pV))
				continue;

      if (auto pGI = dyn_cast<GetElementPtrInst>(U)) {
        if (doReachTainted(dyn_cast<Value>(Inst)))
					return true;
      } else if (auto pBI = dyn_cast<BitCastInst>(U)) {
        if (doReachTainted(dyn_cast<Value>(Inst)))
					return true;
      } else if (auto pCI = dyn_cast<CallInst>(U)) {
				unsigned int arg_n = 0;

				for (auto op = pCI->operands().begin();
									op != pCI->operands().end(); ++op) {

					if (dyn_cast<Value>(op) == pV)
						break;

					arg_n++;
				}
			
				//pCI->dump();
	
				if (Function *pF = pCI->getCalledFunction()) {
					//errs() << "pF->getName: " << pF->getName() << "\n";

					// libc func.
					if (arg_n > pF->arg_size() - 1)
						continue;

					//errs() << "arg_size: " << pF->arg_size() << "\n";

					auto arg = pF->arg_begin();
					for (unsigned int i=0; i<arg_n; i++) {
						arg++;
					}

					//errs() << "arg->dump(): ";
					//arg->dump();

					if (doReachTainted(arg))
						return true;
				}
      } else if (Inst->getOpcode() == Instruction::Store) {
        auto pSI = dyn_cast<StoreInst>(Inst);

        if (pSI->getValueOperand() == pV) {

					Value *pV = pSI->getPointerOperand();

					for (auto U : pV->users()) {
						if (auto pUI = dyn_cast<Instruction>(U)) {

							if (pUI->getOpcode() == Instruction::Load) {
								auto pLI = dyn_cast<LoadInst>(pUI);

								if (doReachTainted(dyn_cast<Value>(pLI)))
									return true;
							}
						}
					}
				}

      }
    }
  }

}

