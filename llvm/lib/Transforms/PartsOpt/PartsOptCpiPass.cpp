//===----------------------------------------------------------------------===//
//
// Author: Zaheer Gauhar <zaheer.gauhar@aalto.fi>
//         Hans Liljestrand <hans.liljestrand@pm.me>
// Copyright (C) 2018 Secure Systems Group, Aalto University <ssg.aalto.fi>
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <llvm/PARTS/PartsIntr.h>
#include "llvm/IR/IRBuilder.h"
#include "llvm/PARTS/PartsTypeMetadata.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Constant.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/PARTS/Parts.h"
#include "llvm/PARTS/PartsLog.h"

using namespace llvm;
using namespace llvm::PARTS;

#define DEBUG_TYPE "PartsOptCpiPass"

//#undef DEBUG_PA
//#define DEBUG_PA(x) x

namespace {

struct PartsOptCpiPass : public FunctionPass {
  static char ID;

  PartsLog_ptr log;

  PartsOptCpiPass() : FunctionPass(ID), log(PartsLog::getLogger(DEBUG_TYPE))
  {
    DEBUG_PA(log->enable());
  }

  bool runOnFunction(Function &F) override;

  void fixDirectFunctionArgs(Function &F, Instruction &I);

  inline void replaceDirectFuncOperand(Function &F, Instruction &I, Value *O, CallInst *CI, unsigned i) {
    auto paced_arg = PartsIntr::pac_pointer(F, I, O);
    CI->setOperand(i, paced_arg);
  }
};

} // anonymous namespace

char PartsOptCpiPass::ID = 0;
static RegisterPass<PartsOptCpiPass> X("parts-opt-cpi", "PARTS CPI pass");

bool PartsOptCpiPass::runOnFunction(Function &F) {
  if (!PARTS::useFeCfi())
    return false;

  for (auto &BB:F){
    for (auto &I: BB) {
      DEBUG_PA(log->debug() << F.getName() << "->" << BB.getName() << "->" << I << "\n");

      const auto IOpcode = I.getOpcode();

      PartsTypeMetadata_ptr MD = nullptr;

      switch(IOpcode) {
        default:
          break;
        case Instruction::Store: {
          assert(isa<StoreInst>(&I));
          auto SI = dyn_cast<StoreInst>(&I);
          auto VO = SI->getValueOperand();

          if (isa<Function>(VO)) {
            log->inc(DEBUG_TYPE ".StoreFunction", true, F.getName()) << "PACing store of function address\n";
            auto paced_arg = PartsIntr::pac_pointer(F, I, VO);
            SI->setOperand(0, paced_arg);
          }
          break;
        }
        case Instruction::Load: {
          break;
        }
        case Instruction::Select: {
          //auto SI = dyn_cast<SelectInst>(&I);
          auto SI = &I;

          for (unsigned i = 0, end = SI->getNumOperands(); i < end; ++i) {
            auto V = SI->getOperand(i);
            if (isa<Function>(V)) {
              const auto VType = V->getType();

              IRBuilder<> Builder(&I);
              // Get declaration for pacia
              auto pacia = Intrinsic::getDeclaration(F.getParent(), Intrinsic::pa_pacia, { VType });
              // Get type_id as Constant
              auto typeIdConstant = PartsTypeMetadata::idConstantFromType(F.getContext(), VType);
              // Create new instruction for pacing the result of select
              auto paced = Builder.CreateCall(pacia, { V, typeIdConstant}, "");
              // Replace any use of select result with the paced replacement
              SI->setOperand(i, paced);
            }
          }
          break;
        }
        case Instruction::Call: {
          fixDirectFunctionArgs(F, I);

          auto CI = dyn_cast<CallInst>(&I);

          if (CI->getCalledFunction() == nullptr) {
            auto O = CI->getCalledValue();

            if (isa<InlineAsm>(O)) {
              // Ignore inline asm
              DEBUG_PA(log->info() << "ignoring inline asm indirect call\n");
            } else if (isa<Function>(O) && dyn_cast<Function>(O)->isIntrinsic()) {
              // Ignore intrinsic calls
              DEBUG_PA(log->info() << "ignoring intrinsic call\n");
            } else if (isa<BitCastOperator>(O)) {
              // Ignore bitcast operator
              DEBUG_PA(log->info() << "ignoring bitcast operator\n");
            } else {
              log->inc(DEBUG_TYPE ".IndirectCall", true, F.getName()) << "found indirect call!!!!\n";
              auto aut_arg = PartsIntr::aut_pointer(F, I, O);
              CI->setCalledFunction(aut_arg);
            }
          }
          break;
        }
      }
    }
  }

  return true;
}

void PartsOptCpiPass::fixDirectFunctionArgs(Function &F, Instruction &I) {
  if (!PARTS::useFeCfi())
    return;

  auto CI = dyn_cast<CallInst>(&I);

  for (auto i = 0U; i < CI->getNumArgOperands(); i++) {
    auto O = CI->getArgOperand(i);

    // First make sure that we're dealing with a function pointer
    if (PartsTypeMetadata::TyIsCodePointer(O->getType())) {
      if (isa<Function>(O)) {
        // The argument is a function address directly taken i.e., func(printf).
        if (!dyn_cast<Function>(O)->isIntrinsic()) {
          // Ignore intrinsics! FIXME: Or should we?
          replaceDirectFuncOperand(F, I, O, CI, i);
        }
      } else if (isa<BitCastOperator>(O)) {
        // This is a bitcast, so src might be directly taken function
        auto BC = dyn_cast<BitCastOperator>(O);
        auto BCO = BC->getOperand(0);

        if (isa<Function>(BCO)) {
          if (!dyn_cast<Function>(BCO)->isIntrinsic()) {
            // Ignore intrinsics! FIXME: Or should we?
            replaceDirectFuncOperand(F, I, O, CI, i);
          }
        }
      }
    }
  }
}
