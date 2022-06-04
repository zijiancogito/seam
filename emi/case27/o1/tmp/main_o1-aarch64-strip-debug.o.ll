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
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !2
  %3 = call i64 @f_scanf_nop(), !insn.addr !3
  %4 = call i64 @rand(i64 %3), !insn.addr !4
  %5 = call i64 @rand(i64 %4), !insn.addr !5
  %6 = call i64 @rand(i64 %5), !insn.addr !6
  %7 = call i64 @f_printf(), !insn.addr !7
  %8 = call i64 @f_printf(), !insn.addr !8
  %9 = sub i64 %2, %1, !insn.addr !9
  %10 = call i64 @f_printf(), !insn.addr !10
  %11 = call i64 @f_printf(), !insn.addr !11
  %factor = mul i64 %6, 8589934112
  %reass.add = add i64 %9, %factor
  %reass.mul = mul i64 %reass.add, 2
  %12 = sub i64 %reass.mul, %5, !insn.addr !12
  %13 = and i64 %12, 4294967295, !insn.addr !12
  ret i64 %13, !insn.addr !13

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_e4:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !14
  %3 = call i64 @rand(i64 %2), !insn.addr !15
  %4 = call i64 @f_scanf_nop(), !insn.addr !16
  %5 = call i64 @f_scanf_nop(), !insn.addr !17
  %6 = call i64 @rand(i64 %5), !insn.addr !18
  %7 = add i64 %2, %1, !insn.addr !19
  %8 = call i64 @f_printf(), !insn.addr !20
  %9 = sub i64 %7, %4, !insn.addr !21
  %10 = add i64 %9, %5, !insn.addr !22
  %11 = mul i64 %10, %3, !insn.addr !23
  %12 = mul i64 %5, %1, !insn.addr !24
  %13 = sub i64 %12, %11, !insn.addr !24
  %14 = and i64 %13, 4294967295, !insn.addr !24
  ret i64 %14, !insn.addr !25

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_154:
  %0 = call i64 @f_scanf_nop(), !insn.addr !26
  %1 = call i64 @rand(i64 %0), !insn.addr !27
  %2 = call i64 @f_scanf_nop(), !insn.addr !28
  %3 = call i64 @f_scanf_nop(), !insn.addr !29
  %4 = call i64 @rand(i64 %3), !insn.addr !30
  %5 = mul i64 %4, 4294967000, !insn.addr !31
  %6 = add i64 %3, 759, !insn.addr !32
  %7 = add i64 %6, %5, !insn.addr !33
  %8 = call i64 @f_printf(), !insn.addr !34
  %9 = sub i64 4294966537, %2, !insn.addr !35
  %10 = add i64 %9, %3, !insn.addr !36
  %11 = sub i64 %10, %5, !insn.addr !37
  %12 = mul i64 %7, %5, !insn.addr !38
  %13 = mul i64 %12, %11, !insn.addr !39
  %14 = and i64 %13, 4294967288, !insn.addr !39
  ret i64 %14, !insn.addr !40

; uselistorder directives
  uselistorder i64 %5, { 1, 0, 2 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_1bc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !41
  %3 = call i64 @rand(i64 %2), !insn.addr !42
  %4 = call i64 @f_scanf_nop(), !insn.addr !43
  %5 = call i64 @f_scanf_nop(), !insn.addr !44
  %6 = call i64 @f_scanf_nop(), !insn.addr !45
  %7 = call i64 @f_printf(), !insn.addr !46
  %8 = call i64 @f_printf(), !insn.addr !47
  %9 = call i64 @f_printf(), !insn.addr !48
  %10 = add i64 %1, 4294966178, !insn.addr !49
  %11 = and i64 %10, 4294967295, !insn.addr !49
  ret i64 %11, !insn.addr !50

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_240:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !51
  %3 = call i64 @rand(i64 %2), !insn.addr !52
  %4 = call i64 @rand(i64 %3), !insn.addr !53
  %5 = call i64 @rand(i64 %4), !insn.addr !54
  %6 = call i64 @f_scanf_nop(), !insn.addr !55
  %7 = mul i64 %1, 4294966625, !insn.addr !56
  %8 = mul i64 %7, %3, !insn.addr !57
  %9 = add i64 %8, %1, !insn.addr !57
  %10 = sub i64 %9, %4, !insn.addr !58
  %11 = and i64 %10, 4294967295, !insn.addr !58
  ret i64 %11, !insn.addr !59

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
  uselistorder i32 1, { 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_290:
  %0 = call i64 @rand(i64 %argc), !insn.addr !60
  %1 = call i64 @f_scanf_nop(), !insn.addr !61
  %2 = call i64 @rand(i64 %1), !insn.addr !62
  %3 = call i64 @rand(i64 %2), !insn.addr !63
  %4 = call i64 @func0(), !insn.addr !64
  %5 = call i64 @func1(), !insn.addr !65
  %6 = call i64 @func2(), !insn.addr !66
  %7 = call i64 @func3(), !insn.addr !67
  %8 = call i64 @func4(), !insn.addr !68
  ret i64 0, !insn.addr !69

; uselistorder directives
  uselistorder i64 ()* @f_scanf_nop, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 (i64)* @rand, { 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 12}
!1 = !{i64 40}
!2 = !{i64 92}
!3 = !{i64 100}
!4 = !{i64 108}
!5 = !{i64 112}
!6 = !{i64 120}
!7 = !{i64 152}
!8 = !{i64 164}
!9 = !{i64 168}
!10 = !{i64 184}
!11 = !{i64 196}
!12 = !{i64 204}
!13 = !{i64 224}
!14 = !{i64 252}
!15 = !{i64 260}
!16 = !{i64 268}
!17 = !{i64 276}
!18 = !{i64 284}
!19 = !{i64 288}
!20 = !{i64 296}
!21 = !{i64 300}
!22 = !{i64 304}
!23 = !{i64 308}
!24 = !{i64 316}
!25 = !{i64 336}
!26 = !{i64 356}
!27 = !{i64 360}
!28 = !{i64 364}
!29 = !{i64 372}
!30 = !{i64 380}
!31 = !{i64 388}
!32 = !{i64 392}
!33 = !{i64 396}
!34 = !{i64 404}
!35 = !{i64 408}
!36 = !{i64 420}
!37 = !{i64 424}
!38 = !{i64 428}
!39 = !{i64 432}
!40 = !{i64 440}
!41 = !{i64 464}
!42 = !{i64 468}
!43 = !{i64 472}
!44 = !{i64 480}
!45 = !{i64 488}
!46 = !{i64 512}
!47 = !{i64 540}
!48 = !{i64 552}
!49 = !{i64 556}
!50 = !{i64 572}
!51 = !{i64 596}
!52 = !{i64 600}
!53 = !{i64 608}
!54 = !{i64 616}
!55 = !{i64 620}
!56 = !{i64 624}
!57 = !{i64 632}
!58 = !{i64 644}
!59 = !{i64 652}
!60 = !{i64 668}
!61 = !{i64 676}
!62 = !{i64 684}
!63 = !{i64 688}
!64 = !{i64 696}
!65 = !{i64 704}
!66 = !{i64 708}
!67 = !{i64 716}
!68 = !{i64 724}
!69 = !{i64 740}
