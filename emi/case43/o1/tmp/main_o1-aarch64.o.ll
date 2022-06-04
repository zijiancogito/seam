source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@global_var_308 = constant [3 x i8] c"%d\00"

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, ptrtoint ([3 x i8]* @global_var_308 to i64), !insn.addr !0
  ret i64 %2, !insn.addr !1
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_14:
  ret i64 ptrtoint ([3 x i8]* @global_var_308 to i64), !insn.addr !2
}

declare i64 @rand(i64) local_unnamed_addr

define i64 @func0() local_unnamed_addr {
dec_label_pc_44:
  %0 = call i64 @f_scanf_nop(), !insn.addr !3
  %1 = call i64 @f_scanf_nop(), !insn.addr !4
  %2 = call i64 @f_scanf_nop(), !insn.addr !5
  %3 = call i64 @f_scanf_nop(), !insn.addr !6
  %4 = call i64 @f_scanf_nop(), !insn.addr !7
  %5 = mul i64 %3, %1, !insn.addr !8
  %6 = call i64 @f_printf(), !insn.addr !9
  %7 = sub i64 %5, %3, !insn.addr !10
  %8 = and i64 %7, 4294967295, !insn.addr !10
  ret i64 %8, !insn.addr !11

; uselistorder directives
  uselistorder i64 %3, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_88:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !12
  %3 = call i64 @rand(i64 %2), !insn.addr !13
  %4 = call i64 @f_scanf_nop(), !insn.addr !14
  %5 = call i64 @f_scanf_nop(), !insn.addr !15
  %6 = call i64 @rand(i64 %5), !insn.addr !16
  %7 = call i64 @f_printf(), !insn.addr !17
  %8 = call i64 @f_printf(), !insn.addr !18
  %9 = add i64 %5, %3, !insn.addr !19
  %10 = mul i64 %9, %6, !insn.addr !20
  %11 = call i64 @f_printf(), !insn.addr !21
  %12 = add i64 %3, 4294967284, !insn.addr !22
  %13 = add i64 %12, %4, !insn.addr !20
  %14 = sub i64 %13, %6, !insn.addr !23
  %15 = add i64 %14, %10, !insn.addr !24
  %16 = and i64 %15, 4294967295, !insn.addr !24
  ret i64 %16, !insn.addr !25

; uselistorder directives
  uselistorder i64 %3, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_114:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !26
  %3 = call i64 @f_scanf_nop(), !insn.addr !27
  %4 = call i64 @rand(i64 %3), !insn.addr !28
  %5 = call i64 @rand(i64 %4), !insn.addr !29
  %6 = call i64 @rand(i64 %5), !insn.addr !30
  %7 = call i64 @f_printf(), !insn.addr !31
  %8 = call i64 @f_printf(), !insn.addr !32
  %9 = call i64 @f_printf(), !insn.addr !33
  %10 = sub i64 770, %1, !insn.addr !34
  %11 = and i64 %10, 4294967295, !insn.addr !34
  ret i64 %11, !insn.addr !35
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_188:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !36
  %3 = call i64 @rand(i64 %2), !insn.addr !37
  %4 = call i64 @rand(i64 %3), !insn.addr !38
  %5 = call i64 @rand(i64 %4), !insn.addr !39
  %6 = call i64 @f_scanf_nop(), !insn.addr !40
  %7 = call i64 @f_printf(), !insn.addr !41
  %8 = call i64 @f_printf(), !insn.addr !42
  %9 = call i64 @f_printf(), !insn.addr !43
  %10 = call i64 @f_printf(), !insn.addr !44
  %11 = call i64 @f_printf(), !insn.addr !45
  %12 = sub i64 %4, %5, !insn.addr !46
  %13 = and i64 %12, 4294967295, !insn.addr !46
  ret i64 %13, !insn.addr !47
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_230:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !48
  %3 = call i64 @rand(i64 %2), !insn.addr !49
  %4 = call i64 @f_scanf_nop(), !insn.addr !50
  %5 = call i64 @f_scanf_nop(), !insn.addr !51
  %6 = call i64 @f_scanf_nop(), !insn.addr !52
  %7 = call i64 @f_printf(), !insn.addr !53
  %8 = call i64 @f_printf(), !insn.addr !54
  %9 = sub i64 4294966620, %2, !insn.addr !55
  %10 = add i64 %9, %3, !insn.addr !56
  %11 = sub i64 %10, %4, !insn.addr !57
  %12 = add i64 %11, %6, !insn.addr !58
  %13 = and i64 %12, 4294967295, !insn.addr !58
  ret i64 %13, !insn.addr !59

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_2a4:
  %0 = call i64 @f_scanf_nop(), !insn.addr !60
  %1 = call i64 @f_scanf_nop(), !insn.addr !61
  %2 = call i64 @rand(i64 %1), !insn.addr !62
  %3 = call i64 @f_scanf_nop(), !insn.addr !63
  %4 = call i64 @func0(), !insn.addr !64
  %5 = call i64 @func1(), !insn.addr !65
  %6 = call i64 @func2(), !insn.addr !66
  %7 = call i64 @func3(), !insn.addr !67
  %8 = call i64 @func4(), !insn.addr !68
  ret i64 0, !insn.addr !69

; uselistorder directives
  uselistorder i64 (i64)* @rand, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_scanf_nop, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @"$d.1"() local_unnamed_addr {
dec_label_pc_308:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1

; uselistorder directives
  uselistorder i32 1, { 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 4}
!1 = !{i64 12}
!2 = !{i64 40}
!3 = !{i64 80}
!4 = !{i64 84}
!5 = !{i64 92}
!6 = !{i64 96}
!7 = !{i64 104}
!8 = !{i64 108}
!9 = !{i64 116}
!10 = !{i64 124}
!11 = !{i64 132}
!12 = !{i64 156}
!13 = !{i64 160}
!14 = !{i64 168}
!15 = !{i64 176}
!16 = !{i64 184}
!17 = !{i64 212}
!18 = !{i64 224}
!19 = !{i64 228}
!20 = !{i64 236}
!21 = !{i64 244}
!22 = !{i64 232}
!23 = !{i64 248}
!24 = !{i64 264}
!25 = !{i64 272}
!26 = !{i64 300}
!27 = !{i64 308}
!28 = !{i64 316}
!29 = !{i64 320}
!30 = !{i64 328}
!31 = !{i64 340}
!32 = !{i64 356}
!33 = !{i64 364}
!34 = !{i64 368}
!35 = !{i64 388}
!36 = !{i64 428}
!37 = !{i64 436}
!38 = !{i64 440}
!39 = !{i64 448}
!40 = !{i64 456}
!41 = !{i64 468}
!42 = !{i64 484}
!43 = !{i64 500}
!44 = !{i64 520}
!45 = !{i64 528}
!46 = !{i64 532}
!47 = !{i64 556}
!48 = !{i64 576}
!49 = !{i64 584}
!50 = !{i64 592}
!51 = !{i64 600}
!52 = !{i64 604}
!53 = !{i64 640}
!54 = !{i64 648}
!55 = !{i64 612}
!56 = !{i64 616}
!57 = !{i64 652}
!58 = !{i64 664}
!59 = !{i64 672}
!60 = !{i64 692}
!61 = !{i64 700}
!62 = !{i64 708}
!63 = !{i64 716}
!64 = !{i64 720}
!65 = !{i64 724}
!66 = !{i64 732}
!67 = !{i64 748}
!68 = !{i64 752}
!69 = !{i64 772}
