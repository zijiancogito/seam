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

define i64 @function_10c() local_unnamed_addr {
dec_label_pc_10c:
  %0 = alloca i64
  %1 = alloca i32
  %2 = load i64, i64* %0
  %3 = load i32, i32* %1
  %4 = trunc i64 %2 to i32, !insn.addr !6
  %5 = mul i32 %3, %4, !insn.addr !6
  %6 = zext i32 %5 to i64, !insn.addr !6
  ret i64 %6, !insn.addr !7
}

define i64 @function_1a8() local_unnamed_addr {
dec_label_pc_1a8:
  ret i64 0, !insn.addr !8
}

define i64 @function_244() local_unnamed_addr {
dec_label_pc_244:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, 4294966178, !insn.addr !9
  %3 = and i64 %2, 4294967295, !insn.addr !9
  ret i64 %3, !insn.addr !10
}

define i64 @function_304() local_unnamed_addr {
dec_label_pc_304:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = and i64 %1, 4294967295, !insn.addr !11
  ret i64 %2, !insn.addr !12

; uselistorder directives
  uselistorder i32 1, { 2, 1, 4, 0, 3 }
}

define i64 @function_374() local_unnamed_addr {
dec_label_pc_374:
  %0 = call i64 @function_244(), !insn.addr !13
  ret i64 0, !insn.addr !14
}

!0 = !{i64 12}
!1 = !{i64 16}
!2 = !{i64 48}
!3 = !{i64 60}
!4 = !{i64 64}
!5 = !{i64 264}
!6 = !{i64 396}
!7 = !{i64 420}
!8 = !{i64 576}
!9 = !{i64 748}
!10 = !{i64 768}
!11 = !{i64 860}
!12 = !{i64 880}
!13 = !{i64 1208}
!14 = !{i64 1272}
