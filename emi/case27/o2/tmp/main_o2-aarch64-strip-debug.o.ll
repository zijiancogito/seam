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
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !2
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_10c:
  ret i64 0, !insn.addr !3
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_1a8:
  ret i64 0, !insn.addr !4
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_244:
  ret i64 0, !insn.addr !5
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_304:
  ret i64 0, !insn.addr !6
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_374:
  ret i64 %argc, !insn.addr !7
}

!0 = !{i64 12}
!1 = !{i64 40}
!2 = !{i64 92}
!3 = !{i64 308}
!4 = !{i64 476}
!5 = !{i64 616}
!6 = !{i64 808}
!7 = !{i64 904}
