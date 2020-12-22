def int_aos_malloc : Intrinsic<[llvm_anyptr_ty], [ llvm_ptr_ty, llvm_i64_ty ], [IntrNoMem]>;
def int_aos_calloc : Intrinsic<[llvm_anyptr_ty], [ llvm_ptr_ty, llvm_i64_ty ], [IntrNoMem]>;
def int_aos_realloc : Intrinsic<[llvm_anyptr_ty], [ llvm_ptr_ty, llvm_i64_ty ], [IntrNoMem]>;
def int_aos_free : Intrinsic<[llvm_anyptr_ty], [ llvm_ptr_ty ], [IntrNoMem]>;
def int_aos_autm : Intrinsic<[llvm_anyptr_ty], [ LLVMMatchType<0> ], [IntrNoMem]>;
//def int_aos_autm : Intrinsic<[llvm_anyptr_ty], [ LLVMMatchType<0> ], [IntrNoMem]>;
//def int_aos_autm : Intrinsic<[llvm_anyptr_ty], [ llvm_ptr_ty ], [IntrNoMem]>;
