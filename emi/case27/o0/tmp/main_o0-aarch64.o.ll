source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, 580, !insn.addr !0
  ret i64 %2, !insn.addr !1
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_30:
  ret i64 580, !insn.addr !2
}

define i64 @f_rand() local_unnamed_addr {
dec_label_pc_60:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !3
}

define i64 @function_78(i64 %arg1, i64 %arg2) local_unnamed_addr {
dec_label_pc_78:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = trunc i64 %2 to i32, !insn.addr !4
  %4 = add i64 %1, -4, !insn.addr !4
  %5 = inttoptr i64 %4 to i32*, !insn.addr !4
  store i32 %3, i32* %5, align 4, !insn.addr !4
  %6 = and i64 %2, 4294967295, !insn.addr !5
  ret i64 %6, !insn.addr !6

; uselistorder directives
  uselistorder i64 %2, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
}

define i64 @func0() local_unnamed_addr {
dec_label_pc_8c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_rand(), !insn.addr !7
  %3 = call i64 @f_scanf_nop(), !insn.addr !8
  %4 = call i64 @f_rand(), !insn.addr !9
  %5 = call i64 @f_rand(), !insn.addr !10
  %6 = call i64 @f_rand(), !insn.addr !11
  %7 = call i64 @f_printf(), !insn.addr !12
  %8 = call i64 @f_printf(), !insn.addr !13
  %9 = call i64 @f_printf(), !insn.addr !14
  %10 = call i64 @f_printf(), !insn.addr !15
  %factor = mul i64 %6, 4294966816
  %11 = sub i64 %2, %1, !insn.addr !16
  %reass.add = add i64 %11, %factor
  %reass.mul = mul i64 %reass.add, 2
  %12 = sub i64 %reass.mul, %5, !insn.addr !17
  %13 = and i64 %12, 4294967295, !insn.addr !18
  ret i64 %13, !insn.addr !19
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_1b4:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !20
  %3 = call i64 @f_rand(), !insn.addr !21
  %4 = call i64 @f_scanf_nop(), !insn.addr !22
  %5 = call i64 @f_scanf_nop(), !insn.addr !23
  %6 = call i64 @f_rand(), !insn.addr !24
  %7 = call i64 @f_printf(), !insn.addr !25
  %8 = add i64 %2, %1, !insn.addr !26
  %9 = sub i64 %8, %4, !insn.addr !27
  %10 = add i64 %9, %5, !insn.addr !28
  %11 = mul i64 %10, %3, !insn.addr !29
  %12 = mul i64 %5, %1, !insn.addr !30
  %13 = sub i64 %12, %11, !insn.addr !31
  %14 = and i64 %13, 4294967295, !insn.addr !32
  ret i64 %14, !insn.addr !33

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_2a4:
  %0 = call i64 @f_scanf_nop(), !insn.addr !34
  %1 = call i64 @f_rand(), !insn.addr !35
  %2 = call i64 @f_scanf_nop(), !insn.addr !36
  %3 = trunc i64 %2 to i32, !insn.addr !37
  %4 = call i64 @f_scanf_nop(), !insn.addr !38
  %5 = trunc i64 %4 to i32, !insn.addr !39
  %6 = call i64 @f_rand(), !insn.addr !40
  %7 = trunc i64 %6 to i32, !insn.addr !41
  %8 = mul i32 %7, -296, !insn.addr !42
  %9 = add i32 %5, 759, !insn.addr !43
  %10 = add i32 %9, %8, !insn.addr !44
  %11 = call i64 @f_printf(), !insn.addr !45
  %12 = sub i32 -759, %3, !insn.addr !46
  %13 = add i32 %12, %5, !insn.addr !47
  %14 = sub i32 %13, %8, !insn.addr !48
  %15 = mul i32 %10, %8, !insn.addr !49
  %16 = mul i32 %15, %14, !insn.addr !50
  %17 = zext i32 %16 to i64, !insn.addr !51
  ret i64 %17, !insn.addr !52

; uselistorder directives
  uselistorder i32 %8, { 1, 0, 2 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_3b8:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !53
  %3 = call i64 @f_rand(), !insn.addr !54
  %4 = call i64 @f_scanf_nop(), !insn.addr !55
  %5 = call i64 @f_scanf_nop(), !insn.addr !56
  %6 = call i64 @f_scanf_nop(), !insn.addr !57
  %7 = call i64 @f_printf(), !insn.addr !58
  %8 = call i64 @f_printf(), !insn.addr !59
  %9 = call i64 @f_printf(), !insn.addr !60
  %10 = add i64 %1, 4294966178, !insn.addr !61
  %11 = and i64 %10, 4294967295, !insn.addr !62
  ret i64 %11, !insn.addr !63

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_4c8:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !64
  %3 = call i64 @f_rand(), !insn.addr !65
  %4 = call i64 @f_rand(), !insn.addr !66
  %5 = call i64 @f_rand(), !insn.addr !67
  %6 = call i64 @f_scanf_nop(), !insn.addr !68
  %7 = mul i64 %1, 4294966625, !insn.addr !69
  %8 = mul i64 %7, %3, !insn.addr !70
  %9 = add i64 %8, %1, !insn.addr !71
  %10 = sub i64 %9, %4, !insn.addr !72
  %11 = and i64 %10, 4294967295, !insn.addr !73
  ret i64 %11, !insn.addr !74

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
  uselistorder i64 4294967295, { 2, 3, 4, 0, 1 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_5c4:
  %0 = call i64 @f_rand(), !insn.addr !75
  %1 = call i64 @f_scanf_nop(), !insn.addr !76
  %2 = call i64 @f_rand(), !insn.addr !77
  %3 = call i64 @f_rand(), !insn.addr !78
  %4 = call i64 @func0(), !insn.addr !79
  %5 = call i64 @func1(), !insn.addr !80
  %6 = call i64 @func2(), !insn.addr !81
  %7 = call i64 @func3(), !insn.addr !82
  %8 = call i64 @func4(), !insn.addr !83
  ret i64 0, !insn.addr !84

; uselistorder directives
  uselistorder i64 ()* @f_scanf_nop, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_rand, { 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @"$d.1"() local_unnamed_addr {
dec_label_pc_644:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1
}

define i64 @function_64c() local_unnamed_addr {
dec_label_pc_64c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1

; uselistorder directives
  uselistorder i32 1, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 16}
!1 = !{i64 28}
!2 = !{i64 68}
!3 = !{i64 104}
!4 = !{i64 120}
!5 = !{i64 124}
!6 = !{i64 136}
!7 = !{i64 172}
!8 = !{i64 180}
!9 = !{i64 188}
!10 = !{i64 196}
!11 = !{i64 204}
!12 = !{i64 288}
!13 = !{i64 312}
!14 = !{i64 352}
!15 = !{i64 392}
!16 = !{i64 332}
!17 = !{i64 412}
!18 = !{i64 420}
!19 = !{i64 432}
!20 = !{i64 468}
!21 = !{i64 476}
!22 = !{i64 484}
!23 = !{i64 492}
!24 = !{i64 500}
!25 = !{i64 544}
!26 = !{i64 580}
!27 = !{i64 532}
!28 = !{i64 588}
!29 = !{i64 596}
!30 = !{i64 612}
!31 = !{i64 652}
!32 = !{i64 660}
!33 = !{i64 672}
!34 = !{i64 704}
!35 = !{i64 712}
!36 = !{i64 720}
!37 = !{i64 724}
!38 = !{i64 728}
!39 = !{i64 732}
!40 = !{i64 736}
!41 = !{i64 740}
!42 = !{i64 768}
!43 = !{i64 864}
!44 = !{i64 872}
!45 = !{i64 884}
!46 = !{i64 896}
!47 = !{i64 904}
!48 = !{i64 912}
!49 = !{i64 920}
!50 = !{i64 928}
!51 = !{i64 936}
!52 = !{i64 948}
!53 = !{i64 984}
!54 = !{i64 992}
!55 = !{i64 1000}
!56 = !{i64 1008}
!57 = !{i64 1016}
!58 = !{i64 1100}
!59 = !{i64 1164}
!60 = !{i64 1188}
!61 = !{i64 1200}
!62 = !{i64 1208}
!63 = !{i64 1220}
!64 = !{i64 1260}
!65 = !{i64 1268}
!66 = !{i64 1276}
!67 = !{i64 1284}
!68 = !{i64 1292}
!69 = !{i64 1324}
!70 = !{i64 1332}
!71 = !{i64 1340}
!72 = !{i64 1452}
!73 = !{i64 1460}
!74 = !{i64 1472}
!75 = !{i64 1500}
!76 = !{i64 1508}
!77 = !{i64 1516}
!78 = !{i64 1524}
!79 = !{i64 1536}
!80 = !{i64 1548}
!81 = !{i64 1552}
!82 = !{i64 1564}
!83 = !{i64 1580}
!84 = !{i64 1600}
