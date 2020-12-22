add_llvm_library(AOS
  AOSGlobalVariableOptPass.cpp
  AOSOptPass.cpp
  AOSMallocPass.cpp
  AOSInputDetectPass.cpp
  AOSMarkTaintPass.cpp
  AOSTaintOptPass.cpp
  AOS.cpp

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/AOS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/Support
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/IR

  DEPENDS
  intrinsics_gen
  LLVMCore
  LLVMSupport
  LLVMTransformUtils
  LLVMCodeGen

  LINK_LIBS
  LLVMCore
  LLVMSupport
  LLVMTransformUtils
  LLVMCodeGen
  )
