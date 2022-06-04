source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

define i64 @function_0() local_unnamed_addr {
dec_label_pc_0:
  br label %dec_label_pc_10, !insn.addr !0

dec_label_pc_10:                                  ; preds = %dec_label_pc_10, %dec_label_pc_0
  br label %dec_label_pc_10, !insn.addr !1
}

define i64 @function_14() local_unnamed_addr {
dec_label_pc_14:
  %0 = alloca i32
  %1 = load i32, i32* %0
  %2 = zext i32 %1 to i64, !insn.addr !2
  ret i64 %2, !insn.addr !3
}

define i64 @function_40() local_unnamed_addr {
dec_label_pc_40:
  %0 = call i64 @function_40(), !insn.addr !4
  ret i64 %0, !insn.addr !4
}

define i64 @function_44() local_unnamed_addr {
dec_label_pc_44:
  %0 = alloca i32
  %1 = load i32, i32* %0
  %2 = zext i32 %1 to i64, !insn.addr !5
  ret i64 %2, !insn.addr !6
}

define i64 @function_cc() local_unnamed_addr {
dec_label_pc_cc:
  %0 = alloca i32
  %1 = load i32, i32* %0
  %2 = add i32 %1, 233, !insn.addr !7
  %3 = zext i32 %2 to i64, !insn.addr !7
  ret i64 %3, !insn.addr !8
}

define i64 @function_164() local_unnamed_addr {
dec_label_pc_164:
  %0 = alloca i64
  %1 = alloca i32
  %2 = load i64, i64* %0
  %3 = load i32, i32* %1
  %4 = load i32, i32* %1
  %5 = trunc i64 %2 to i32, !insn.addr !9
  %6 = add i32 %5, -619, !insn.addr !10
  %7 = mul i32 %5, 619, !insn.addr !11
  %.neg3 = mul i32 %7, %4
  %.neg4 = sub i32 %4, %5, !insn.addr !11
  %8 = add i32 %.neg4, %.neg3, !insn.addr !12
  %9 = mul i32 %8, %5, !insn.addr !13
  %10 = mul i32 %6, %3, !insn.addr !14
  %11 = add i32 %9, %10, !insn.addr !14
  %12 = zext i32 %11 to i64, !insn.addr !14
  ret i64 %12, !insn.addr !15

; uselistorder directives
  uselistorder i32 %5, { 1, 0, 2, 3 }
  uselistorder i32 %4, { 1, 0 }
  uselistorder i32* %1, { 1, 0 }
}

define i64 @function_208() local_unnamed_addr {
dec_label_pc_208:
  ret i64 0, !insn.addr !16
}

define i64 @function_2b0() local_unnamed_addr {
dec_label_pc_2b0:
  %0 = alloca i64
  %1 = alloca i32
  %2 = load i64, i64* %0
  %3 = load i64, i64* %0
  %4 = load i32, i32* %1
  %5 = load i32, i32* %1
  %6 = sub i64 %3, %2, !insn.addr !17
  %7 = trunc i64 %6 to i32, !insn.addr !18
  %8 = add i32 %7, -849, !insn.addr !18
  %9 = trunc i64 %2 to i32, !insn.addr !19
  %10 = mul i32 %8, %4, !insn.addr !20
  %11 = sub i32 %4, %9, !insn.addr !19
  %12 = add i32 %11, %7, !insn.addr !21
  %13 = sub i32 %12, %5, !insn.addr !22
  %14 = add i32 %13, %10, !insn.addr !20
  %15 = zext i32 %14 to i64, !insn.addr !20
  ret i64 %15, !insn.addr !23

; uselistorder directives
  uselistorder i32 %4, { 1, 0 }
  uselistorder i32* %1, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
  uselistorder i32 1, { 6, 1, 5, 0, 4, 3, 2 }
}

define i64 @function_358() local_unnamed_addr {
dec_label_pc_358:
  ret i64 0, !insn.addr !24
}

!0 = !{i64 12}
!1 = !{i64 16}
!2 = !{i64 48}
!3 = !{i64 60}
!4 = !{i64 64}
!5 = !{i64 180}
!6 = !{i64 200}
!7 = !{i64 332}
!8 = !{i64 352}
!9 = !{i64 384}
!10 = !{i64 476}
!11 = !{i64 448}
!12 = !{i64 484}
!13 = !{i64 488}
!14 = !{i64 492}
!15 = !{i64 516}
!16 = !{i64 684}
!17 = !{i64 776}
!18 = !{i64 808}
!19 = !{i64 816}
!20 = !{i64 828}
!21 = !{i64 820}
!22 = !{i64 824}
!23 = !{i64 852}
!24 = !{i64 1360}
