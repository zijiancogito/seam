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
  ret i64 0, !insn.addr !5
}

define i64 @function_e0() local_unnamed_addr {
dec_label_pc_e0:
  %0 = alloca i64
  %1 = alloca i32
  %2 = load i64, i64* %0
  %3 = load i32, i32* %1
  %4 = load i32, i32* %1
  %5 = trunc i64 %2 to i32, !insn.addr !6
  %6 = add i32 %3, %5, !insn.addr !6
  %7 = add i32 %6, %4, !insn.addr !7
  %8 = mul i32 %7, %5, !insn.addr !8
  %9 = sub i32 %8, %3, !insn.addr !9
  %10 = zext i32 %9 to i64, !insn.addr !10
  ret i64 %10, !insn.addr !11

; uselistorder directives
  uselistorder i32* %1, { 1, 0 }
}

define i64 @function_1b4() local_unnamed_addr {
dec_label_pc_1b4:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = add i64 %1, 583, !insn.addr !12
  %4 = mul i64 %2, 508, !insn.addr !13
  %5 = mul i64 %4, %3, !insn.addr !14
  %6 = add i64 %5, 508, !insn.addr !15
  %7 = mul i64 %6, %5, !insn.addr !16
  %8 = add i64 %7, %2, !insn.addr !16
  %9 = and i64 %8, 4294967295, !insn.addr !16
  ret i64 %9, !insn.addr !17

; uselistorder directives
  uselistorder i64 %2, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
  uselistorder i64 508, { 1, 0 }
}

define i64 @function_244() local_unnamed_addr {
dec_label_pc_244:
  ret i64 498, !insn.addr !18
}

define i64 @function_290() local_unnamed_addr {
dec_label_pc_290:
  %0 = alloca i32
  %1 = load i32, i32* %0
  %2 = mul i32 %1, -7853, !insn.addr !19
  %3 = zext i32 %2 to i64, !insn.addr !19
  ret i64 %3, !insn.addr !20

; uselistorder directives
  uselistorder i32 1, { 4, 1, 3, 0, 2 }
}

define i64 @function_31c() local_unnamed_addr {
dec_label_pc_31c:
  ret i64 0, !insn.addr !21
}

!0 = !{i64 12}
!1 = !{i64 16}
!2 = !{i64 48}
!3 = !{i64 60}
!4 = !{i64 64}
!5 = !{i64 220}
!6 = !{i64 356}
!7 = !{i64 360}
!8 = !{i64 368}
!9 = !{i64 400}
!10 = !{i64 404}
!11 = !{i64 432}
!12 = !{i64 528}
!13 = !{i64 532}
!14 = !{i64 540}
!15 = !{i64 548}
!16 = !{i64 568}
!17 = !{i64 576}
!18 = !{i64 652}
!19 = !{i64 784}
!20 = !{i64 792}
!21 = !{i64 1240}
