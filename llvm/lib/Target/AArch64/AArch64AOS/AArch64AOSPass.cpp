#include "AArch64.h"
#include "AArch64Subtarget.h"
#include "AArch64RegisterInfo.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "AArch64MachineFunctionInfo.h"

#include "llvm/AOS/AOS.h"

#define DEBUG_TYPE "AArch64AOSPass"

STATISTIC(StatNumPACMA,
            DEBUG_TYPE "Number of PACMA intrinsics replaced");

STATISTIC(StatNumXPACM,
            DEBUG_TYPE "Number of XPACM intrinsics replaced");

STATISTIC(StatNumAUTM,
            DEBUG_TYPE "Number of AUTM intrinsics replaced");

using namespace llvm;

namespace {
 class AArch64AOSPass : public MachineFunctionPass {

 public:
   static char ID;

   AArch64AOSPass() : MachineFunctionPass(ID) {}

   StringRef getPassName() const override { return DEBUG_TYPE; }

   virtual bool doInitialization(Module &M) override;
   bool runOnMachineFunction(MachineFunction &) override;

 private:
   const AArch64Subtarget *STI = nullptr;
   const AArch64InstrInfo *TII = nullptr;
   inline bool handleInstruction(MachineFunction &MF, MachineBasicBlock &MBB,
                                      MachineBasicBlock::instr_iterator &MIi);
  };
}

char AArch64AOSPass::ID = 0;
FunctionPass *llvm::createAArch64AOSPass() { return new AArch64AOSPass(); }

bool AArch64AOSPass::doInitialization(Module &M) {
  return true;
}

bool AArch64AOSPass::runOnMachineFunction(MachineFunction &MF) {
  bool modified = false;
  STI = &MF.getSubtarget<AArch64Subtarget>();
  TII = STI->getInstrInfo();

  for (auto &MBB : MF) {
    for (auto MIi = MBB.instr_begin(), MIie = MBB.instr_end(); MIi != MIie;) {
      auto MIk = MIi++;

      switch (MIk->getOpcode()) {
        case AArch64::AOS_MALLOC: {
          auto MIj = MIk;
          auto MIjb = MBB.instr_begin();

          for (; MIj != MIjb; MIj--) {
            if (MIj->getOpcode() == 383) { // find bl @malloc
              MIj++;

              BuildMI(MBB, MIj, MIk->getDebugLoc(), TII->get(AArch64::AOS_PACMA), MIk->getOperand(1).getReg())
                .addUse(AArch64::SP)
                //.addUse(AArch64::XZR)
                .addReg(MIk->getOperand(0).getReg());
              BuildMI(MBB, MIk, MIk->getDebugLoc(), TII->get(AArch64::AOS_BNDSTR), MIk->getOperand(1).getReg())
                .addUse(MIk->getOperand(0).getReg());

              break;
            }
          }

          assert(MIj != MIjb && "Couldn't find bl @malloc\n");

          MIk->removeFromParent();
          modified = true;
          ++StatNumPACMA;
          break;
        }
        case AArch64::AOS_CALLOC: {
          auto MIj = MIk;
          auto MIjb = MBB.instr_begin();

          for (; MIj != MIjb; MIj--) {
            if (MIj->getOpcode() == 383) { // find bl @calloc
              MIj++;

              BuildMI(MBB, MIj, MIk->getDebugLoc(), TII->get(AArch64::AOS_PACMA), MIk->getOperand(1).getReg())
                .addUse(AArch64::SP)
                //.addUse(AArch64::XZR)
                .addReg(MIk->getOperand(0).getReg());
              BuildMI(MBB, MIk, MIk->getDebugLoc(), TII->get(AArch64::AOS_BNDSTR), MIk->getOperand(1).getReg())
                .addUse(MIk->getOperand(0).getReg());

              break;
            }
          }

          assert(MIj != MIjb && "Couldn't find bl @calloc\n");

          MIk->removeFromParent();
          modified = true;
          ++StatNumPACMA;
          break;
        }
        case AArch64::AOS_REALLOC: {
          auto MIj = MIk;
          auto MIjb = MBB.instr_begin();

          for (; MIj != MIjb; MIj--) {
            if (MIj->getOpcode() == 383) { // find bl @realloc
              BuildMI(MBB, MIj, MIk->getDebugLoc(), TII->get(AArch64::AOS_BNDCLR), MIk->getOperand(1).getReg());
              BuildMI(MBB, MIj, MIk->getDebugLoc(), TII->get(AArch64::AOS_XPACM), MIk->getOperand(1).getReg());

              MIj++;

              BuildMI(MBB, MIj, MIk->getDebugLoc(), TII->get(AArch64::AOS_PACMA), AArch64::X0)
                .addUse(AArch64::SP)
                //.addUse(AArch64::XZR)
                .addReg(MIk->getOperand(0).getReg());
              BuildMI(MBB, MIk, MIk->getDebugLoc(), TII->get(AArch64::AOS_BNDSTR), AArch64::X0)
                .addUse(MIk->getOperand(0).getReg());
              break;
            }
          }

          assert(MIj != MIjb && "Couldn't find bl @realloc\n");

          MIk->removeFromParent();
          modified = true;
          ++StatNumPACMA;
          break;
        }
        case AArch64::AOS_FREE: {
          auto MIj = MIk;
          auto MIjb = MBB.instr_begin();

          //for (; MIj != MIjb; MIj--) {
          for (; MIj != MIjb;) {
            if (MIj->getOpcode() == 383) { // find bl @free
              BuildMI(MBB, MIj, MIk->getDebugLoc(), TII->get(AArch64::AOS_BNDCLR), AArch64::X0);
              BuildMI(MBB, MIj, MIk->getDebugLoc(), TII->get(AArch64::AOS_XPACM), AArch64::X0);
              //BuildMI(MBB, MIj, MIk->getDebugLoc(), TII->get(AArch64::AOS_XPACM), MIk->getOperand(0).getReg());

              BuildMI(MBB, MIk, MIk->getDebugLoc(), TII->get(AArch64::AOS_PACMA), MIk->getOperand(0).getReg())
                .addUse(AArch64::SP)
                //.addUse(AArch64::XZR)
                //.addUse(AArch64::Z31);
                .addUse(AArch64::XZR);

              //assert(MIj != MIjb && "Couldn't find bl @free\n");
              MIk->removeFromParent();
              modified = true;
              ++StatNumXPACM;


              break;
            }

            MIj--;
          }

          if (MIj == MIjb) {
            BuildMI(MBB, MIjb, MIk->getDebugLoc(), TII->get(AArch64::AOS_BNDCLR), AArch64::X0);
            BuildMI(MBB, MIjb, MIk->getDebugLoc(), TII->get(AArch64::AOS_XPACM), AArch64::X0);

            BuildMI(MBB, MIk, MIk->getDebugLoc(), TII->get(AArch64::AOS_PACMA), MIk->getOperand(0).getReg())
              .addUse(AArch64::SP)
              //.addUse(AArch64::XZR)
              //.addUse(AArch64::Z31);
              .addUse(AArch64::XZR);
            printf("Couldn't find bl @free\n");

           //assert(MIj != MIjb && "Couldn't find bl @free\n");
            MIk->removeFromParent();
            modified = true;
            ++StatNumXPACM;
          }

          break;
        }
        case AArch64::AOS_AUTM: {
          BuildMI(MBB, MIk, MIk->getDebugLoc(), TII->get(AArch64::AOS_CHECK), MIk->getOperand(0).getReg());

          MIk->removeFromParent();
          modified = true;
          ++StatNumAUTM;
          break;
        }
        default:
          break;
      }
    }
  }

  return modified;
}

