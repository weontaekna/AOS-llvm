; ------------------------------------------------------------------------
; Author: Hans Liljestrand <hans.liljestrand@pm.me>
; Copyright (C) 2018 Secure Systems Group, Aalto University <ssg.aalto.fi>
;
; This file is distributed under the University of Illinois Open Source
; License. See LICENSE.TXT for details.
; ------------------------------------------------------------------------
; Test that we only sign/auth the data pointer argument passed in a registers and
; that we do not sign the data pointer arguments passed on the stack. The latter one
; should have already be sign and need no instrumentation by our spill pass.
;
; FIXME: We need stop after the aarch64-early-parts-dpi, but currently we do not have support for
; that in our pass (use of INITIALIZE_PASS())
; RUN: llc -mtriple=aarch64-none-linux-gnu -mattr=v8.3a -parts-dpi --stop-before=greedy -verify-machineinstrs < %s | FileCheck %s
;

define void @spill_one_data_pointer(i64* %d0, i64* %d1, i64 %d2, i64 %d3, i64 %d4, i64 %d5, i64 %d6, i64 %d7, i64* %dataptronstack, i64* %dataptronstack2, i64* %dataptronstack3) {
entry:
  %0 = call i64* @llvm.parts.data.pointer.argument.p0i64(i64* %d0)
  %1 = call i64* @llvm.parts.data.pointer.argument.p0i64(i64* %d1)
  %2 = call i64* @llvm.parts.data.pointer.argument.p0i64(i64* %dataptronstack)
  %3 = call i64* @llvm.parts.data.pointer.argument.p0i64(i64* %dataptronstack2)
  %4 = call i64* @llvm.parts.data.pointer.argument.p0i64(i64* %dataptronstack3)
; CHECK: [[VREG1:%[0-9]+]]:gpr64 = PARTS_DATA_PTR [[VREG1]]
; CHECK: [[VREG2:%[0-9]+]]:gpr64 = PARTS_DATA_PTR [[VREG2]]
; CHECK-NOT: PARTS_DATA_PTR
  call void asm sideeffect "nop", "~{x0},~{x1},~{x2},~{x3},~{x4},~{x5},~{x6},~{x7},~{x8},~{x9},~{x10},~{x11},~{x12},~{x13},~{x14},~{x15},~{x16},~{x17},~{x18},~{x19},~{x20},~{x21},~{x22},~{x23},~{x24},~{x25},~{x26},~{x27},~{x28},~{x29},~{x30},~{x31}"() #1
  call void @func2(i64* %0, i64* %1, i64 %d2, i64 %d3, i64 %d4, i64 %d5, i64 %d6, i64 %d7, i64* %2, i64* %3, i64* %4)
  ret void
}

declare void @func2(i64*, i64*, i64, i64, i64, i64, i64, i64, i64*, i64*, i64*)
declare i64* @llvm.parts.data.pointer.argument.p0i64(i64*)

attributes #1 = { nounwind }
