source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@global_var_2e8 = constant [3 x i8] c"%d\00"

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, ptrtoint ([3 x i8]* @global_var_2e8 to i64), !insn.addr !0
  ret i64 %2, !insn.addr !1
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_14:
  ret i64 ptrtoint ([3 x i8]* @global_var_2e8 to i64), !insn.addr !2
}

declare i64 @rand(i64) local_unnamed_addr

define i64 @func0() local_unnamed_addr {
dec_label_pc_44:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !3
  %3 = call i64 @f_scanf_nop(), !insn.addr !4
  %4 = call i64 @rand(i64 %3), !insn.addr !5
  %5 = call i64 @rand(i64 %4), !insn.addr !6
  %6 = call i64 @rand(i64 %5), !insn.addr !7
  %7 = call i64 @f_printf(), !insn.addr !8
  %8 = call i64 @f_printf(), !insn.addr !9
  %9 = sub i64 %2, %1, !insn.addr !10
  %10 = call i64 @f_printf(), !insn.addr !11
  %11 = call i64 @f_printf(), !insn.addr !12
  %factor = mul i64 %6, 8589934112
  %reass.add = add i64 %9, %factor
  %reass.mul = mul i64 %reass.add, 2
  %12 = sub i64 %reass.mul, %5, !insn.addr !13
  %13 = and i64 %12, 4294967295, !insn.addr !13
  ret i64 %13, !insn.addr !14

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_e4:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !15
  %3 = call i64 @rand(i64 %2), !insn.addr !16
  %4 = call i64 @f_scanf_nop(), !insn.addr !17
  %5 = call i64 @f_scanf_nop(), !insn.addr !18
  %6 = call i64 @rand(i64 %5), !insn.addr !19
  %7 = add i64 %2, %1, !insn.addr !20
  %8 = call i64 @f_printf(), !insn.addr !21
  %9 = sub i64 %7, %4, !insn.addr !22
  %10 = add i64 %9, %5, !insn.addr !23
  %11 = mul i64 %10, %3, !insn.addr !24
  %12 = mul i64 %5, %1, !insn.addr !25
  %13 = sub i64 %12, %11, !insn.addr !25
  %14 = and i64 %13, 4294967295, !insn.addr !25
  ret i64 %14, !insn.addr !26

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_154:
  %0 = call i64 @f_scanf_nop(), !insn.addr !27
  %1 = call i64 @rand(i64 %0), !insn.addr !28
  %2 = call i64 @f_scanf_nop(), !insn.addr !29
  %3 = call i64 @f_scanf_nop(), !insn.addr !30
  %4 = call i64 @rand(i64 %3), !insn.addr !31
  %5 = mul i64 %4, 4294967000, !insn.addr !32
  %6 = add i64 %3, 759, !insn.addr !33
  %7 = add i64 %6, %5, !insn.addr !34
  %8 = call i64 @f_printf(), !insn.addr !35
  %9 = sub i64 4294966537, %2, !insn.addr !36
  %10 = add i64 %9, %3, !insn.addr !37
  %11 = sub i64 %10, %5, !insn.addr !38
  %12 = mul i64 %7, %5, !insn.addr !39
  %13 = mul i64 %12, %11, !insn.addr !40
  %14 = and i64 %13, 4294967288, !insn.addr !40
  ret i64 %14, !insn.addr !41

; uselistorder directives
  uselistorder i64 %5, { 1, 0, 2 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_1bc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !42
  %3 = call i64 @rand(i64 %2), !insn.addr !43
  %4 = call i64 @f_scanf_nop(), !insn.addr !44
  %5 = call i64 @f_scanf_nop(), !insn.addr !45
  %6 = call i64 @f_scanf_nop(), !insn.addr !46
  %7 = call i64 @f_printf(), !insn.addr !47
  %8 = call i64 @f_printf(), !insn.addr !48
  %9 = call i64 @f_printf(), !insn.addr !49
  %10 = add i64 %1, 4294966178, !insn.addr !50
  %11 = and i64 %10, 4294967295, !insn.addr !50
  ret i64 %11, !insn.addr !51

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_240:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !52
  %3 = call i64 @rand(i64 %2), !insn.addr !53
  %4 = call i64 @rand(i64 %3), !insn.addr !54
  %5 = call i64 @rand(i64 %4), !insn.addr !55
  %6 = call i64 @f_scanf_nop(), !insn.addr !56
  %7 = mul i64 %1, 4294966625, !insn.addr !57
  %8 = mul i64 %7, %3, !insn.addr !58
  %9 = add i64 %8, %1, !insn.addr !58
  %10 = sub i64 %9, %4, !insn.addr !59
  %11 = and i64 %10, 4294967295, !insn.addr !59
  ret i64 %11, !insn.addr !60

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_290:
  %0 = call i64 @rand(i64 %argc), !insn.addr !61
  %1 = call i64 @f_scanf_nop(), !insn.addr !62
  %2 = call i64 @rand(i64 %1), !insn.addr !63
  %3 = call i64 @rand(i64 %2), !insn.addr !64
  %4 = call i64 @func0(), !insn.addr !65
  %5 = call i64 @func1(), !insn.addr !66
  %6 = call i64 @func2(), !insn.addr !67
  %7 = call i64 @func3(), !insn.addr !68
  %8 = call i64 @func4(), !insn.addr !69
  ret i64 0, !insn.addr !70

; uselistorder directives
  uselistorder i64 ()* @f_scanf_nop, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 (i64)* @rand, { 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @"$d.1"() local_unnamed_addr {
dec_label_pc_2e8:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1

; uselistorder directives
  uselistorder i32 1, { 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 4}
!1 = !{i64 12}
!2 = !{i64 40}
!3 = !{i64 92}
!4 = !{i64 100}
!5 = !{i64 108}
!6 = !{i64 112}
!7 = !{i64 120}
!8 = !{i64 152}
!9 = !{i64 164}
!10 = !{i64 168}
!11 = !{i64 184}
!12 = !{i64 196}
!13 = !{i64 204}
!14 = !{i64 224}
!15 = !{i64 252}
!16 = !{i64 260}
!17 = !{i64 268}
!18 = !{i64 276}
!19 = !{i64 284}
!20 = !{i64 288}
!21 = !{i64 296}
!22 = !{i64 300}
!23 = !{i64 304}
!24 = !{i64 308}
!25 = !{i64 316}
!26 = !{i64 336}
!27 = !{i64 356}
!28 = !{i64 360}
!29 = !{i64 364}
!30 = !{i64 372}
!31 = !{i64 380}
!32 = !{i64 388}
!33 = !{i64 392}
!34 = !{i64 396}
!35 = !{i64 404}
!36 = !{i64 408}
!37 = !{i64 420}
!38 = !{i64 424}
!39 = !{i64 428}
!40 = !{i64 432}
!41 = !{i64 440}
!42 = !{i64 464}
!43 = !{i64 468}
!44 = !{i64 472}
!45 = !{i64 480}
!46 = !{i64 488}
!47 = !{i64 512}
!48 = !{i64 540}
!49 = !{i64 552}
!50 = !{i64 556}
!51 = !{i64 572}
!52 = !{i64 596}
!53 = !{i64 600}
!54 = !{i64 608}
!55 = !{i64 616}
!56 = !{i64 620}
!57 = !{i64 624}
!58 = !{i64 632}
!59 = !{i64 644}
!60 = !{i64 652}
!61 = !{i64 668}
!62 = !{i64 676}
!63 = !{i64 684}
!64 = !{i64 688}
!65 = !{i64 696}
!66 = !{i64 704}
!67 = !{i64 708}
!68 = !{i64 716}
!69 = !{i64 724}
!70 = !{i64 740}
