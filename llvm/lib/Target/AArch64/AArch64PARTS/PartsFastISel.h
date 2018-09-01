//===----------------------------------------------------------------------===//
//
// Author: Hans Liljestrand <hans.liljestrand@pm.me>
// Copyright: Secure Systems Group, Aalto University https://ssg.aalto.fi/
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_PARTSFASTISEL_H
#define LLVM_PARTSFASTISEL_H

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/FunctionLoweringInfo.h"
#include "llvm/CodeGen/FastISel.h"

namespace llvm {

class PartsFastISel;
typedef std::shared_ptr<PartsFastISel> PartsFastISel_ptr;

class PartsFastISel {
  FunctionLoweringInfo &FuncInfo;

protected:
public:

  PartsFastISel() = delete;
  PartsFastISel(FunctionLoweringInfo &FuncInfo);

  void addPartsTypeMetadata(MachineInstrBuilder &MIB, MDNode *partsType);

  void addMetadataToStore(MachineInstrBuilder &MIB, MDNode *partsType);
  void addMetadataToLoad(MachineInstrBuilder &MIB, MDNode *partsType);

  void addMetadataToCall(MachineInstrBuilder &MIB, MDNode *partsType);
  void addMetadataToCall(MachineInstrBuilder &MIB, FastISel::CallLoweringInfo &CLI, unsigned reg);

  static PartsFastISel_ptr get(FunctionLoweringInfo &FuncInfo);

};

} // namespace llvm

#endif //LLVM_PARTSFASTISEL_H
