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
  %2 = mul i32 %1, %1, !insn.addr !5
  %3 = sub i32 %2, %1, !insn.addr !6
  %4 = zext i32 %3 to i64, !insn.addr !6
  ret i64 %4, !insn.addr !7

; uselistorder directives
  uselistorder i32 %1, { 2, 1, 0 }
}

define i64 @function_c4() local_unnamed_addr {
dec_label_pc_c4:
  %0 = alloca i64
  %1 = alloca i32
  %2 = load i64, i64* %0
  %3 = load i32, i32* %1
  %4 = trunc i64 %2 to i32, !insn.addr !8
  %5 = add i32 %4, -12, !insn.addr !9
  %6 = add i32 %5, %3, !insn.addr !10
  %7 = zext i32 %6 to i64, !insn.addr !10
  ret i64 %7, !insn.addr !11
}

define i64 @function_17c() local_unnamed_addr {
dec_label_pc_17c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = sub i64 770, %1, !insn.addr !12
  %3 = and i64 %2, 4294967295, !insn.addr !12
  ret i64 %3, !insn.addr !13
}

define i64 @function_21c() local_unnamed_addr {
dec_label_pc_21c:
  ret i64 0, !insn.addr !14
}

define i64 @function_2f0() local_unnamed_addr {
dec_label_pc_2f0:
  %0 = alloca i32
  %1 = load i32, i32* %0
  %2 = load i32, i32* %0
  %3 = add i32 %1, -676, !insn.addr !15
  %4 = sub i32 %3, %2, !insn.addr !16
  %5 = zext i32 %4 to i64, !insn.addr !16
  ret i64 %5, !insn.addr !17

; uselistorder directives
  uselistorder i32* %0, { 1, 0 }
  uselistorder i32 1, { 5, 1, 4, 0, 3, 2 }
}

define i64 @function_398() local_unnamed_addr {
dec_label_pc_398:
  ret i64 0, !insn.addr !18
}

!0 = !{i64 12}
!1 = !{i64 16}
!2 = !{i64 48}
!3 = !{i64 60}
!4 = !{i64 64}
!5 = !{i64 160}
!6 = !{i64 176}
!7 = !{i64 192}
!8 = !{i64 328}
!9 = !{i64 348}
!10 = !{i64 368}
!11 = !{i64 376}
!12 = !{i64 512}
!13 = !{i64 536}
!14 = !{i64 748}
!15 = !{i64 892}
!16 = !{i64 908}
!17 = !{i64 916}
!18 = !{i64 1568}
