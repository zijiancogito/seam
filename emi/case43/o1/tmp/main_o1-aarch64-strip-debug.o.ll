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

declare i64 @rand(i64) local_unnamed_addr

define i64 @func0() local_unnamed_addr {
dec_label_pc_44:
  %0 = call i64 @f_scanf_nop(), !insn.addr !2
  %1 = call i64 @f_scanf_nop(), !insn.addr !3
  %2 = call i64 @f_scanf_nop(), !insn.addr !4
  %3 = call i64 @f_scanf_nop(), !insn.addr !5
  %4 = call i64 @f_scanf_nop(), !insn.addr !6
  %5 = mul i64 %3, %1, !insn.addr !7
  %6 = call i64 @f_printf(), !insn.addr !8
  %7 = sub i64 %5, %3, !insn.addr !9
  %8 = and i64 %7, 4294967295, !insn.addr !9
  ret i64 %8, !insn.addr !10

; uselistorder directives
  uselistorder i64 %3, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_88:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !11
  %3 = call i64 @rand(i64 %2), !insn.addr !12
  %4 = call i64 @f_scanf_nop(), !insn.addr !13
  %5 = call i64 @f_scanf_nop(), !insn.addr !14
  %6 = call i64 @rand(i64 %5), !insn.addr !15
  %7 = call i64 @f_printf(), !insn.addr !16
  %8 = call i64 @f_printf(), !insn.addr !17
  %9 = add i64 %5, %3, !insn.addr !18
  %10 = mul i64 %9, %6, !insn.addr !19
  %11 = call i64 @f_printf(), !insn.addr !20
  %12 = add i64 %3, 4294967284, !insn.addr !21
  %13 = add i64 %12, %4, !insn.addr !19
  %14 = sub i64 %13, %6, !insn.addr !22
  %15 = add i64 %14, %10, !insn.addr !23
  %16 = and i64 %15, 4294967295, !insn.addr !23
  ret i64 %16, !insn.addr !24

; uselistorder directives
  uselistorder i64 %3, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_114:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !25
  %3 = call i64 @f_scanf_nop(), !insn.addr !26
  %4 = call i64 @rand(i64 %3), !insn.addr !27
  %5 = call i64 @rand(i64 %4), !insn.addr !28
  %6 = call i64 @rand(i64 %5), !insn.addr !29
  %7 = call i64 @f_printf(), !insn.addr !30
  %8 = call i64 @f_printf(), !insn.addr !31
  %9 = call i64 @f_printf(), !insn.addr !32
  %10 = sub i64 770, %1, !insn.addr !33
  %11 = and i64 %10, 4294967295, !insn.addr !33
  ret i64 %11, !insn.addr !34
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_188:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !35
  %3 = call i64 @rand(i64 %2), !insn.addr !36
  %4 = call i64 @rand(i64 %3), !insn.addr !37
  %5 = call i64 @rand(i64 %4), !insn.addr !38
  %6 = call i64 @f_scanf_nop(), !insn.addr !39
  %7 = call i64 @f_printf(), !insn.addr !40
  %8 = call i64 @f_printf(), !insn.addr !41
  %9 = call i64 @f_printf(), !insn.addr !42
  %10 = call i64 @f_printf(), !insn.addr !43
  %11 = call i64 @f_printf(), !insn.addr !44
  %12 = sub i64 %4, %5, !insn.addr !45
  %13 = and i64 %12, 4294967295, !insn.addr !45
  ret i64 %13, !insn.addr !46
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_230:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !47
  %3 = call i64 @rand(i64 %2), !insn.addr !48
  %4 = call i64 @f_scanf_nop(), !insn.addr !49
  %5 = call i64 @f_scanf_nop(), !insn.addr !50
  %6 = call i64 @f_scanf_nop(), !insn.addr !51
  %7 = call i64 @f_printf(), !insn.addr !52
  %8 = call i64 @f_printf(), !insn.addr !53
  %9 = sub i64 4294966620, %2, !insn.addr !54
  %10 = add i64 %9, %3, !insn.addr !55
  %11 = sub i64 %10, %4, !insn.addr !56
  %12 = add i64 %11, %6, !insn.addr !57
  %13 = and i64 %12, 4294967295, !insn.addr !57
  ret i64 %13, !insn.addr !58

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i32 1, { 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_2a4:
  %0 = call i64 @f_scanf_nop(), !insn.addr !59
  %1 = call i64 @f_scanf_nop(), !insn.addr !60
  %2 = call i64 @rand(i64 %1), !insn.addr !61
  %3 = call i64 @f_scanf_nop(), !insn.addr !62
  %4 = call i64 @func0(), !insn.addr !63
  %5 = call i64 @func1(), !insn.addr !64
  %6 = call i64 @func2(), !insn.addr !65
  %7 = call i64 @func3(), !insn.addr !66
  %8 = call i64 @func4(), !insn.addr !67
  ret i64 0, !insn.addr !68

; uselistorder directives
  uselistorder i64 (i64)* @rand, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_scanf_nop, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 12}
!1 = !{i64 40}
!2 = !{i64 80}
!3 = !{i64 84}
!4 = !{i64 92}
!5 = !{i64 96}
!6 = !{i64 104}
!7 = !{i64 108}
!8 = !{i64 116}
!9 = !{i64 124}
!10 = !{i64 132}
!11 = !{i64 156}
!12 = !{i64 160}
!13 = !{i64 168}
!14 = !{i64 176}
!15 = !{i64 184}
!16 = !{i64 212}
!17 = !{i64 224}
!18 = !{i64 228}
!19 = !{i64 236}
!20 = !{i64 244}
!21 = !{i64 232}
!22 = !{i64 248}
!23 = !{i64 264}
!24 = !{i64 272}
!25 = !{i64 300}
!26 = !{i64 308}
!27 = !{i64 316}
!28 = !{i64 320}
!29 = !{i64 328}
!30 = !{i64 340}
!31 = !{i64 356}
!32 = !{i64 364}
!33 = !{i64 368}
!34 = !{i64 388}
!35 = !{i64 428}
!36 = !{i64 436}
!37 = !{i64 440}
!38 = !{i64 448}
!39 = !{i64 456}
!40 = !{i64 468}
!41 = !{i64 484}
!42 = !{i64 500}
!43 = !{i64 520}
!44 = !{i64 528}
!45 = !{i64 532}
!46 = !{i64 556}
!47 = !{i64 576}
!48 = !{i64 584}
!49 = !{i64 592}
!50 = !{i64 600}
!51 = !{i64 604}
!52 = !{i64 640}
!53 = !{i64 648}
!54 = !{i64 612}
!55 = !{i64 616}
!56 = !{i64 652}
!57 = !{i64 664}
!58 = !{i64 672}
!59 = !{i64 692}
!60 = !{i64 700}
!61 = !{i64 708}
!62 = !{i64 716}
!63 = !{i64 720}
!64 = !{i64 724}
!65 = !{i64 732}
!66 = !{i64 748}
!67 = !{i64 752}
!68 = !{i64 772}
