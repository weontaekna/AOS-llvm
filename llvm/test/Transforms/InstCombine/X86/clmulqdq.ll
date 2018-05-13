; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -instcombine -S | FileCheck %s

declare <2 x i64> @llvm.x86.pclmulqdq(<2 x i64>, <2 x i64>, i8)

define <2 x i64> @test_demanded_elts_pclmulqdq_0(<2 x i64> %a0, <2 x i64> %a1) {
; CHECK-LABEL: @test_demanded_elts_pclmulqdq_0(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> [[A0:%.*]], <2 x i64> [[A1:%.*]], i8 0)
; CHECK-NEXT:    ret <2 x i64> [[TMP1]]
;
  %1 = insertelement <2 x i64> %a0, i64 1, i64 1
  %2 = insertelement <2 x i64> %a1, i64 1, i64 1
  %3 = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %1, <2 x i64> %2, i8 0)
  ret <2 x i64> %3
}

define <2 x i64> @test_demanded_elts_pclmulqdq_1(<2 x i64> %a0, <2 x i64> %a1) {
; CHECK-LABEL: @test_demanded_elts_pclmulqdq_1(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> <i64 undef, i64 1>, <2 x i64> [[A1:%.*]], i8 1)
; CHECK-NEXT:    ret <2 x i64> [[TMP1]]
;
  %1 = insertelement <2 x i64> %a0, i64 1, i64 1
  %2 = insertelement <2 x i64> %a1, i64 1, i64 1
  %3 = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %1, <2 x i64> %2, i8 1)
  ret <2 x i64> %3
}

define <2 x i64> @test_demanded_elts_pclmulqdq_16(<2 x i64> %a0, <2 x i64> %a1) {
; CHECK-LABEL: @test_demanded_elts_pclmulqdq_16(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> [[A0:%.*]], <2 x i64> <i64 undef, i64 1>, i8 16)
; CHECK-NEXT:    ret <2 x i64> [[TMP1]]
;
  %1 = insertelement <2 x i64> %a0, i64 1, i64 1
  %2 = insertelement <2 x i64> %a1, i64 1, i64 1
  %3 = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %1, <2 x i64> %2, i8 16)
  ret <2 x i64> %3
}

define <2 x i64> @test_demanded_elts_pclmulqdq_17(<2 x i64> %a0, <2 x i64> %a1) {
; CHECK-LABEL: @test_demanded_elts_pclmulqdq_17(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> <i64 undef, i64 1>, <2 x i64> <i64 undef, i64 1>, i8 17)
; CHECK-NEXT:    ret <2 x i64> [[TMP1]]
;
  %1 = insertelement <2 x i64> %a0, i64 1, i64 1
  %2 = insertelement <2 x i64> %a1, i64 1, i64 1
  %3 = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %1, <2 x i64> %2, i8 17)
  ret <2 x i64> %3
}

define <2 x i64> @test_demanded_elts_pclmulqdq_undef_0() {
; CHECK-LABEL: @test_demanded_elts_pclmulqdq_undef_0(
; CHECK-NEXT:    ret <2 x i64> zeroinitializer
;
  %1 = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> <i64 undef, i64 1>, <2 x i64> <i64 undef, i64 1>, i8 0)
  ret <2 x i64> %1
}

define <2 x i64> @test_demanded_elts_pclmulqdq_undef_1() {
; CHECK-LABEL: @test_demanded_elts_pclmulqdq_undef_1(
; CHECK-NEXT:    ret <2 x i64> zeroinitializer
;
  %1 = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> <i64 1, i64 undef>, <2 x i64> <i64 undef, i64 1>, i8 1)
  ret <2 x i64> %1
}

define <2 x i64> @test_demanded_elts_pclmulqdq_undef_16() {
; CHECK-LABEL: @test_demanded_elts_pclmulqdq_undef_16(
; CHECK-NEXT:    ret <2 x i64> zeroinitializer
;
  %1 = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> <i64 undef, i64 1>, <2 x i64> <i64 1, i64 undef>, i8 16)
  ret <2 x i64> %1
}

define <2 x i64> @test_demanded_elts_pclmulqdq_undef_17() {
; CHECK-LABEL: @test_demanded_elts_pclmulqdq_undef_17(
; CHECK-NEXT:    ret <2 x i64> zeroinitializer
;
  %1 = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> <i64 1, i64 undef>, <2 x i64> <i64 1, i64 undef>, i8 17)
  ret <2 x i64> %1
}