source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  ret i64 0, !insn.addr !0
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_30:
  ret i64 0, !insn.addr !1
}

define i64 @f_rand() local_unnamed_addr {
dec_label_pc_60:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !2
}

define i64 @function_78(i64 %arg1, i64 %arg2) local_unnamed_addr {
dec_label_pc_78:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = trunc i64 %2 to i32, !insn.addr !3
  %4 = add i64 %1, -4, !insn.addr !3
  %5 = inttoptr i64 %4 to i32*, !insn.addr !3
  store i32 %3, i32* %5, align 4, !insn.addr !3
  %6 = and i64 %2, 4294967295, !insn.addr !4
  ret i64 %6, !insn.addr !5

; uselistorder directives
  uselistorder i64 %2, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
}

define i64 @func0() local_unnamed_addr {
dec_label_pc_8c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_rand(), !insn.addr !6
  %3 = call i64 @f_scanf_nop(), !insn.addr !7
  %4 = call i64 @f_rand(), !insn.addr !8
  %5 = call i64 @f_rand(), !insn.addr !9
  %6 = call i64 @f_rand(), !insn.addr !10
  %7 = call i64 @f_printf(), !insn.addr !11
  %8 = call i64 @f_printf(), !insn.addr !12
  %9 = call i64 @f_printf(), !insn.addr !13
  %10 = call i64 @f_printf(), !insn.addr !14
  %factor = mul i64 %6, 4294966816
  %11 = sub i64 %2, %1, !insn.addr !15
  %reass.add = add i64 %11, %factor
  %reass.mul = mul i64 %reass.add, 2
  %12 = sub i64 %reass.mul, %5, !insn.addr !16
  %13 = and i64 %12, 4294967295, !insn.addr !17
  ret i64 %13, !insn.addr !18
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_1b4:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !19
  %3 = call i64 @f_rand(), !insn.addr !20
  %4 = call i64 @f_scanf_nop(), !insn.addr !21
  %5 = call i64 @f_scanf_nop(), !insn.addr !22
  %6 = call i64 @f_rand(), !insn.addr !23
  %7 = call i64 @f_printf(), !insn.addr !24
  %8 = add i64 %2, %1, !insn.addr !25
  %9 = sub i64 %8, %4, !insn.addr !26
  %10 = add i64 %9, %5, !insn.addr !27
  %11 = mul i64 %10, %3, !insn.addr !28
  %12 = mul i64 %5, %1, !insn.addr !29
  %13 = sub i64 %12, %11, !insn.addr !30
  %14 = and i64 %13, 4294967295, !insn.addr !31
  ret i64 %14, !insn.addr !32

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_2a4:
  %0 = call i64 @f_scanf_nop(), !insn.addr !33
  %1 = call i64 @f_rand(), !insn.addr !34
  %2 = call i64 @f_scanf_nop(), !insn.addr !35
  %3 = trunc i64 %2 to i32, !insn.addr !36
  %4 = call i64 @f_scanf_nop(), !insn.addr !37
  %5 = trunc i64 %4 to i32, !insn.addr !38
  %6 = call i64 @f_rand(), !insn.addr !39
  %7 = trunc i64 %6 to i32, !insn.addr !40
  %8 = mul i32 %7, -296, !insn.addr !41
  %9 = add i32 %5, 759, !insn.addr !42
  %10 = add i32 %9, %8, !insn.addr !43
  %11 = call i64 @f_printf(), !insn.addr !44
  %12 = sub i32 -759, %3, !insn.addr !45
  %13 = add i32 %12, %5, !insn.addr !46
  %14 = sub i32 %13, %8, !insn.addr !47
  %15 = mul i32 %10, %8, !insn.addr !48
  %16 = mul i32 %15, %14, !insn.addr !49
  %17 = zext i32 %16 to i64, !insn.addr !50
  ret i64 %17, !insn.addr !51

; uselistorder directives
  uselistorder i32 %8, { 1, 0, 2 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_3b8:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !52
  %3 = call i64 @f_rand(), !insn.addr !53
  %4 = call i64 @f_scanf_nop(), !insn.addr !54
  %5 = call i64 @f_scanf_nop(), !insn.addr !55
  %6 = call i64 @f_scanf_nop(), !insn.addr !56
  %7 = call i64 @f_printf(), !insn.addr !57
  %8 = call i64 @f_printf(), !insn.addr !58
  %9 = call i64 @f_printf(), !insn.addr !59
  %10 = add i64 %1, 4294966178, !insn.addr !60
  %11 = and i64 %10, 4294967295, !insn.addr !61
  ret i64 %11, !insn.addr !62

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_4c8:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !63
  %3 = call i64 @f_rand(), !insn.addr !64
  %4 = call i64 @f_rand(), !insn.addr !65
  %5 = call i64 @f_rand(), !insn.addr !66
  %6 = call i64 @f_scanf_nop(), !insn.addr !67
  %7 = mul i64 %1, 4294966625, !insn.addr !68
  %8 = mul i64 %7, %3, !insn.addr !69
  %9 = add i64 %8, %1, !insn.addr !70
  %10 = sub i64 %9, %4, !insn.addr !71
  %11 = and i64 %10, 4294967295, !insn.addr !72
  ret i64 %11, !insn.addr !73

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
  uselistorder i64 4294967295, { 2, 3, 4, 0, 1 }
  uselistorder i32 1, { 5, 4, 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_5c4:
  %0 = call i64 @f_rand(), !insn.addr !74
  %1 = call i64 @f_scanf_nop(), !insn.addr !75
  %2 = call i64 @f_rand(), !insn.addr !76
  %3 = call i64 @f_rand(), !insn.addr !77
  %4 = call i64 @func0(), !insn.addr !78
  %5 = call i64 @func1(), !insn.addr !79
  %6 = call i64 @func2(), !insn.addr !80
  %7 = call i64 @func3(), !insn.addr !81
  %8 = call i64 @func4(), !insn.addr !82
  ret i64 0, !insn.addr !83

; uselistorder directives
  uselistorder i64 ()* @f_scanf_nop, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_rand, { 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 28}
!1 = !{i64 68}
!2 = !{i64 104}
!3 = !{i64 120}
!4 = !{i64 124}
!5 = !{i64 136}
!6 = !{i64 172}
!7 = !{i64 180}
!8 = !{i64 188}
!9 = !{i64 196}
!10 = !{i64 204}
!11 = !{i64 288}
!12 = !{i64 312}
!13 = !{i64 352}
!14 = !{i64 392}
!15 = !{i64 332}
!16 = !{i64 412}
!17 = !{i64 420}
!18 = !{i64 432}
!19 = !{i64 468}
!20 = !{i64 476}
!21 = !{i64 484}
!22 = !{i64 492}
!23 = !{i64 500}
!24 = !{i64 544}
!25 = !{i64 580}
!26 = !{i64 532}
!27 = !{i64 588}
!28 = !{i64 596}
!29 = !{i64 612}
!30 = !{i64 652}
!31 = !{i64 660}
!32 = !{i64 672}
!33 = !{i64 704}
!34 = !{i64 712}
!35 = !{i64 720}
!36 = !{i64 724}
!37 = !{i64 728}
!38 = !{i64 732}
!39 = !{i64 736}
!40 = !{i64 740}
!41 = !{i64 768}
!42 = !{i64 864}
!43 = !{i64 872}
!44 = !{i64 884}
!45 = !{i64 896}
!46 = !{i64 904}
!47 = !{i64 912}
!48 = !{i64 920}
!49 = !{i64 928}
!50 = !{i64 936}
!51 = !{i64 948}
!52 = !{i64 984}
!53 = !{i64 992}
!54 = !{i64 1000}
!55 = !{i64 1008}
!56 = !{i64 1016}
!57 = !{i64 1100}
!58 = !{i64 1164}
!59 = !{i64 1188}
!60 = !{i64 1200}
!61 = !{i64 1208}
!62 = !{i64 1220}
!63 = !{i64 1260}
!64 = !{i64 1268}
!65 = !{i64 1276}
!66 = !{i64 1284}
!67 = !{i64 1292}
!68 = !{i64 1324}
!69 = !{i64 1332}
!70 = !{i64 1340}
!71 = !{i64 1452}
!72 = !{i64 1460}
!73 = !{i64 1472}
!74 = !{i64 1500}
!75 = !{i64 1508}
!76 = !{i64 1516}
!77 = !{i64 1524}
!78 = !{i64 1536}
!79 = !{i64 1548}
!80 = !{i64 1552}
!81 = !{i64 1564}
!82 = !{i64 1580}
!83 = !{i64 1600}
