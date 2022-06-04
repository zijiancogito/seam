source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  ret i64 0, !insn.addr !0
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_14:
  ret i64 0, !insn.addr !1
}

define i64 @func0() local_unnamed_addr {
dec_label_pc_44:
  ret i64 0, !insn.addr !2
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_cc:
  ret i64 0, !insn.addr !3
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_164:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !4
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_208:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !5
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_2b0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !6

; uselistorder directives
  uselistorder i32 1, { 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_358:
  ret i64 0, !insn.addr !7
}

!0 = !{i64 12}
!1 = !{i64 40}
!2 = !{i64 120}
!3 = !{i64 240}
!4 = !{i64 376}
!5 = !{i64 540}
!6 = !{i64 716}
!7 = !{i64 892}
