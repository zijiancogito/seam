source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, 252, !insn.addr !0
  ret i64 %2, !insn.addr !1
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_14:
  ret i64 252, !insn.addr !2
}

define i64 @func0() local_unnamed_addr {
dec_label_pc_44:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !3
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_10c:
  ret i64 252, !insn.addr !4
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_1a8:
  ret i64 252, !insn.addr !5
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_244:
  ret i64 252, !insn.addr !6
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_304:
  ret i64 252, !insn.addr !7
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_374:
  ret i64 %argc, !insn.addr !8
}

define i64 @"$d.1"() local_unnamed_addr {
dec_label_pc_4fc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1
}

define i64 @function_504() local_unnamed_addr {
dec_label_pc_504:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1
}

define i64 @function_50c() local_unnamed_addr {
dec_label_pc_50c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1

; uselistorder directives
  uselistorder i32 1, { 4, 3, 2, 1, 0 }
}

!0 = !{i64 4}
!1 = !{i64 12}
!2 = !{i64 40}
!3 = !{i64 92}
!4 = !{i64 308}
!5 = !{i64 460}
!6 = !{i64 616}
!7 = !{i64 808}
!8 = !{i64 904}
