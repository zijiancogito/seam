source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, 548, !insn.addr !0
  ret i64 %2, !insn.addr !1
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_14:
  ret i64 548, !insn.addr !2
}

define i64 @func0() local_unnamed_addr {
dec_label_pc_44:
  ret i64 548, !insn.addr !3
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_c4:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !4
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_17c:
  %0 = call i64 @"$d.1"(), !insn.addr !5
  ret i64 548, !insn.addr !6
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_21c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !7
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_2f0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !8
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_398:
  ret i64 548, !insn.addr !9
}

define i64 @"$d.1"() local_unnamed_addr {
dec_label_pc_624:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1
}

define i64 @function_62c() local_unnamed_addr {
dec_label_pc_62c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1
}

define i64 @function_634() local_unnamed_addr {
dec_label_pc_634:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1

; uselistorder directives
  uselistorder i32 1, { 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 4}
!1 = !{i64 12}
!2 = !{i64 40}
!3 = !{i64 96}
!4 = !{i64 216}
!5 = !{i64 424}
!6 = !{i64 436}
!7 = !{i64 576}
!8 = !{i64 768}
!9 = !{i64 960}
