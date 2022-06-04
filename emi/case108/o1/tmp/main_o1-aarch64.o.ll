source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@global_var_2b0 = constant [3 x i8] c"%d\00"
@0 = external global i32

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, ptrtoint ([3 x i8]* @global_var_2b0 to i64), !insn.addr !0
  ret i64 %2, !insn.addr !1
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_14:
  ret i64 ptrtoint ([3 x i8]* @global_var_2b0 to i64), !insn.addr !2
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
  %8 = add i64 %2, %1, !insn.addr !9
  %9 = add i64 %8, %6, !insn.addr !10
  %10 = sub i64 %1, %3, !insn.addr !11
  %11 = mul i64 %9, %3, !insn.addr !12
  %12 = add i64 %10, %11, !insn.addr !12
  %13 = call i64 @f_printf(), !insn.addr !13
  %14 = call i64 @f_printf(), !insn.addr !14
  %15 = mul i64 %12, %4, !insn.addr !15
  %16 = and i64 %15, 4294967295, !insn.addr !15
  ret i64 %16, !insn.addr !16

; uselistorder directives
  uselistorder i64 %3, { 1, 0, 2 }
  uselistorder i64 %1, { 2, 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_bc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !17
  %3 = call i64 @f_scanf_nop(), !insn.addr !18
  %4 = call i64 @rand(i64 %3), !insn.addr !19
  %5 = call i64 @rand(i64 %4), !insn.addr !20
  %6 = call i64 @rand(i64 %5), !insn.addr !21
  %7 = mul i64 %4, %2, !insn.addr !22
  %8 = add i64 %7, %3, !insn.addr !23
  %9 = call i64 @f_printf(), !insn.addr !24
  %10 = add i64 %4, %3, !insn.addr !25
  %11 = add i64 %10, %6, !insn.addr !26
  %12 = call i64 @f_printf(), !insn.addr !27
  %13 = add i64 %2, %1, !insn.addr !28
  %14 = add i64 %13, %8, !insn.addr !29
  %15 = mul i64 %14, %1, !insn.addr !30
  %16 = mul i64 %8, %2, !insn.addr !31
  %17 = call i64 @f_printf(), !insn.addr !32
  %18 = sub i64 %7, %16
  %19 = sub i64 %15, %8, !insn.addr !33
  %20 = mul i64 %6, %7, !insn.addr !34
  %21 = mul i64 %20, %11, !insn.addr !35
  %22 = mul i64 %21, %18, !insn.addr !36
  %23 = add i64 %19, %22, !insn.addr !36
  %24 = and i64 %23, 4294967295, !insn.addr !36
  ret i64 %24, !insn.addr !37

; uselistorder directives
  uselistorder i64 %7, { 0, 2, 1 }
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_164:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = call i64 @f_scanf_nop(), !insn.addr !38
  %4 = call i64 @rand(i64 %3), !insn.addr !39
  %5 = call i64 @rand(i64 %4), !insn.addr !40
  %6 = call i64 @rand(i64 %5), !insn.addr !41
  %7 = call i64 @rand(i64 %6), !insn.addr !42
  %8 = add i64 %5, 508, !insn.addr !43
  %9 = call i64 @f_printf(), !insn.addr !44
  %10 = sub i64 %2, %5, !insn.addr !45
  %11 = add i64 %1, 583, !insn.addr !46
  %12 = sub i64 %10, %6, !insn.addr !47
  %13 = mul i64 %11, %2, !insn.addr !48
  %14 = mul i64 %13, %8, !insn.addr !49
  %15 = add i64 %14, %8, !insn.addr !50
  %16 = mul i64 %15, %14, !insn.addr !51
  %17 = add i64 %12, %16, !insn.addr !51
  %18 = and i64 %17, 4294967295, !insn.addr !51
  ret i64 %18, !insn.addr !52

; uselistorder directives
  uselistorder i64* %0, { 1, 0 }
}

define i64 @func3(i64 %arg1) local_unnamed_addr {
dec_label_pc_1d8:
  %0 = call i64 @f_scanf_nop(), !insn.addr !53
  %1 = call i64 @rand(i64 %0), !insn.addr !54
  %2 = call i64 @f_scanf_nop(), !insn.addr !55
  %3 = call i64 @rand(i64 %2), !insn.addr !56
  %4 = call i64 @rand(i64 %3), !insn.addr !57
  %5 = sub i64 498, %4, !insn.addr !58
  %6 = and i64 %5, 4294967295, !insn.addr !58
  ret i64 %6, !insn.addr !59
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_204:
  %0 = call i64 @f_scanf_nop(), !insn.addr !60
  %1 = call i64 @f_scanf_nop(), !insn.addr !61
  %2 = call i64 @f_scanf_nop(), !insn.addr !62
  %3 = call i64 @f_scanf_nop(), !insn.addr !63
  %4 = call i64 @rand(i64 %3), !insn.addr !64
  %5 = call i64 @f_printf(), !insn.addr !65
  %6 = call i64 @f_printf(), !insn.addr !66
  %7 = mul i64 %1, 4294959443, !insn.addr !67
  %8 = and i64 %7, 4294967295, !insn.addr !67
  ret i64 %8, !insn.addr !68

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_258:
  %0 = call i64 @f_scanf_nop(), !insn.addr !69
  %1 = call i64 @rand(i64 %0), !insn.addr !70
  %2 = call i64 @f_scanf_nop(), !insn.addr !71
  %3 = call i64 @rand(i64 %2), !insn.addr !72
  %4 = call i64 @func0(), !insn.addr !73
  %5 = call i64 @func1(), !insn.addr !74
  %6 = call i64 @func2(), !insn.addr !75
  %7 = call i64 @func3(i64 ptrtoint (i32* @0 to i64)), !insn.addr !76
  %8 = call i64 @func4(), !insn.addr !77
  ret i64 0, !insn.addr !78

; uselistorder directives
  uselistorder i64 (i64)* @rand, { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_scanf_nop, { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @"$d.1"() local_unnamed_addr {
dec_label_pc_2b0:
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
!4 = !{i64 100}
!5 = !{i64 108}
!6 = !{i64 116}
!7 = !{i64 120}
!8 = !{i64 132}
!9 = !{i64 136}
!10 = !{i64 140}
!11 = !{i64 144}
!12 = !{i64 148}
!13 = !{i64 152}
!14 = !{i64 160}
!15 = !{i64 164}
!16 = !{i64 184}
!17 = !{i64 216}
!18 = !{i64 224}
!19 = !{i64 232}
!20 = !{i64 240}
!21 = !{i64 244}
!22 = !{i64 248}
!23 = !{i64 252}
!24 = !{i64 264}
!25 = !{i64 268}
!26 = !{i64 272}
!27 = !{i64 280}
!28 = !{i64 284}
!29 = !{i64 288}
!30 = !{i64 296}
!31 = !{i64 300}
!32 = !{i64 312}
!33 = !{i64 324}
!34 = !{i64 292}
!35 = !{i64 320}
!36 = !{i64 344}
!37 = !{i64 352}
!38 = !{i64 384}
!39 = !{i64 388}
!40 = !{i64 392}
!41 = !{i64 400}
!42 = !{i64 408}
!43 = !{i64 412}
!44 = !{i64 420}
!45 = !{i64 424}
!46 = !{i64 428}
!47 = !{i64 432}
!48 = !{i64 436}
!49 = !{i64 452}
!50 = !{i64 456}
!51 = !{i64 460}
!52 = !{i64 468}
!53 = !{i64 480}
!54 = !{i64 484}
!55 = !{i64 488}
!56 = !{i64 492}
!57 = !{i64 496}
!58 = !{i64 504}
!59 = !{i64 512}
!60 = !{i64 528}
!61 = !{i64 536}
!62 = !{i64 544}
!63 = !{i64 548}
!64 = !{i64 552}
!65 = !{i64 568}
!66 = !{i64 576}
!67 = !{i64 588}
!68 = !{i64 596}
!69 = !{i64 612}
!70 = !{i64 620}
!71 = !{i64 628}
!72 = !{i64 632}
!73 = !{i64 640}
!74 = !{i64 648}
!75 = !{i64 660}
!76 = !{i64 664}
!77 = !{i64 668}
!78 = !{i64 684}
