//===----------------------------------------------------------------------===//
//
// Author: Hans Liljestrand <hans.liljestrand@pm.me>
// Copyright (C) 2018 Secure Systems Group, Aalto University <ssg.aalto.fi>
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <iostream>
// LLVM includes
#include "AArch64.h"
#include "AArch64Subtarget.h"
#include "AArch64RegisterInfo.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
// PARTS includes
#include "llvm/PARTS/PartsTypeMetadata.h"
#include "llvm/PARTS/PartsEventCount.h"
#include "llvm/PARTS/Parts.h"
#include "PartsUtils.h"

#define DEBUG_TYPE "AArch64PartsRuntimeStatistics"

using namespace llvm;
using namespace llvm::PARTS;

namespace {
 class AArch64PartsRuntimeStatistics : public MachineFunctionPass {

 public:
   static char ID;

   AArch64PartsRuntimeStatistics() : MachineFunctionPass(ID) {}

   StringRef getPassName() const override { return DEBUG_TYPE; }

   virtual bool doInitialization(Module &M) override;
   bool runOnMachineFunction(MachineFunction &) override;

 private:
   const AArch64Subtarget *STI = nullptr;
   const AArch64InstrInfo *TII = nullptr;
   PartsUtils_ptr  partsUtils = nullptr;
   Function *funcCountCodePtrBranch = nullptr;
   Function *funcCountCodePtrCreate = nullptr;
   inline bool handleInstruction(MachineFunction &MF, MachineBasicBlock &MBB, MachineBasicBlock::instr_iterator &MIi);
  };
} // end anonymous namespace

FunctionPass *llvm::createAArch64PartsPassRuntimeStatistics() {

  return new AArch64PartsRuntimeStatistics();
}

char AArch64PartsRuntimeStatistics::ID = 0;

bool AArch64PartsRuntimeStatistics::doInitialization(Module &M) {
  funcCountCodePtrBranch = PartsEventCount::getFuncCodePointerBranch(M);
  funcCountCodePtrCreate = PartsEventCount::getFuncCodePointerCreate(M);
  return true;
}

bool AArch64PartsRuntimeStatistics::runOnMachineFunction(MachineFunction &MF) {
  bool found = false;

  STI = &MF.getSubtarget<AArch64Subtarget>();
  TII = STI->getInstrInfo();
  partsUtils = PartsUtils::get(STI->getRegisterInfo(), TII);

  for (auto &MBB : MF)
    for (auto MIi = MBB.instr_begin(), MIie = MBB.instr_end(); MIi != MIie; ++MIi)
      found = handleInstruction(MF, MBB, MIi) || found;

  return found;
}

/**
 *
 * @param MF
 * @param MBB
 * @param MIi
 * @return  return true when changing something, otherwise false
 */
inline bool AArch64PartsRuntimeStatistics::handleInstruction(MachineFunction &MF,
                                                   MachineBasicBlock &MBB,
                                                   MachineBasicBlock::instr_iterator &MIi) {
  //const auto MIOpcode = MIi->getOpcode();

  return false;
}
