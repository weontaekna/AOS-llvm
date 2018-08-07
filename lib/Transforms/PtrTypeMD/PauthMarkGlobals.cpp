// PauthMarkGlobals.cpp - Code for Pointer Authentication
//
//                     The LLVM Compiler Infrastructure
//
// This code is released under Apache 2.0 license.
// Author: Hans Liljestrand
// Copyright: Secure Systems Group, Aalto University https://ssg.aalto.fi/
//

#include <llvm/IR/IRBuilder.h>
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "../../Target/AArch64/PointerAuthentication.h"

using namespace llvm;

#define DEBUG_TYPE "PauthOptPauthMarkGlobals"
#define TAG KYEL DEBUG_TYPE ": "

namespace {

struct PauthMarkGlobals: public ModulePass {
  static char ID; // Pass identification, replacement for typeid

  PauthMarkGlobals() : ModulePass(ID) {}

  bool runOnModule(Module &F) override;
};

} // anonyous namespace

char PauthMarkGlobals::ID = 0;
static RegisterPass<PauthMarkGlobals> X("pauth-markglobals", "PAC argv for main call");

bool PauthMarkGlobals::runOnModule(Module &M)
{
  int marked_data_pointers = 0;
  int marked_code_pointers = 0;

  auto data_type_ids = std::list<PA::pauth_type_id>(0);
  auto code_type_ids = std::list<PA::pauth_type_id>(0);

  // Automatically annotate pointer globals
  for (auto GI = M.global_begin(); GI != M.global_end(); GI++) {
    auto Ty = GI->getOperand(0)->getType();
    errs() << "----checking";
    GI->dump();
    errs() << "hasSection " << GI->hasSection() << " -> " << GI->getSection() << "\n";
    //if (Ty->isPointerTy() && !GI->hasSection()) {

    //GI->getSection()

    //if (Ty->isPointerTy() && !GI->hasSection()) {
    if (Ty->isPointerTy()) {
      auto type_id = PA::createPauthTypeId(Ty);

      errs() << "seems to be a pointer " << type_id << "\n";

      if (PA::isInstruction(type_id)) {
        marked_code_pointers++; // This should eventually be put in .code_pauth
        GI->setSection(".code_pauth");
        errs() << "----adding me a code pointer\n";
        code_type_ids.push_back(type_id);
      } else {
        marked_data_pointers++;
        GI->setSection(".data_pauth");
        errs() << "----adding me a data pointer\n";
        data_type_ids.push_back(type_id);
      }

      // TODO: add the type_ids into their own sections (.data_pauth_type_id, .code_pauth_type_id)
    } else {
      errs() << "not a pointer\n";
    }
  }

  for (auto type_id : data_type_ids) {
    errs() << "-----------------------------------------------------------------------------------\n";
    ConstantInt* type_id_Constant = ConstantInt::get(Type::getInt64Ty(M.getContext()), type_id);

    GlobalVariable *g = new GlobalVariable(M, Type::getInt64Ty(M.getContext()), true, GlobalValue::PrivateLinkage, type_id_Constant);
    g->setExternallyInitialized(false);
    g->setSection(".data_type_id");
  }

  DEBUG(errs() << getPassName() << ": moved " << marked_data_pointers << "+" << marked_code_pointers <<
               " globals to pauth data/code section(s)\n");

  return (marked_code_pointers+marked_code_pointers) > 0;
}
