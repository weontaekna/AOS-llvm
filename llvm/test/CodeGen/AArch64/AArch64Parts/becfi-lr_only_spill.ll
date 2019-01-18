; RUN: llc -mtriple=aarch64-none-linux-gnu -mattr=v8.3a -parts-becfi < %s | FileCheck %s
target triple = "aarch64"

; Check that leaf functions aren't instrumented
define void @leaf() #0 {
entry:
;   CHECK-NO: pacib
    ret void
;   CHECK-NO: autib
}

; Make sure that LR-only spill is instrumented
define void @func() #1 {
entry:
;   CHECK: pacib
    call void @leaf()
;   CHECK: autib
    ret void
}

attributes #0 = { noinline nounwind optnone }
