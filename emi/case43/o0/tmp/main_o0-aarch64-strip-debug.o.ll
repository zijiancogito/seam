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
  %0 = call i64 @f_scanf_nop(), !insn.addr !6
  %1 = call i64 @f_scanf_nop(), !insn.addr !7
  %2 = call i64 @f_scanf_nop(), !insn.addr !8
  %3 = call i64 @f_scanf_nop(), !insn.addr !9
  %4 = call i64 @f_scanf_nop(), !insn.addr !10
  %5 = mul i64 %3, %1, !insn.addr !11
  %6 = call i64 @f_printf(), !insn.addr !12
  %7 = sub i64 %5, %3, !insn.addr !13
  %8 = and i64 %7, 4294967295, !insn.addr !14
  ret i64 %8, !insn.addr !15

; uselistorder directives
  uselistorder i64 %3, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_160:
  %0 = call i64 @f_rand(), !insn.addr !16
  %1 = call i64 @f_rand(), !insn.addr !17
  %2 = call i64 @f_scanf_nop(), !insn.addr !18
  %3 = call i64 @f_scanf_nop(), !insn.addr !19
  %4 = call i64 @f_rand(), !insn.addr !20
  %5 = call i64 @f_printf(), !insn.addr !21
  %6 = call i64 @f_printf(), !insn.addr !22
  %7 = add i64 %3, %1, !insn.addr !23
  %8 = mul i64 %7, %4, !insn.addr !24
  %9 = call i64 @f_printf(), !insn.addr !25
  %10 = add i64 %1, 4294967284, !insn.addr !26
  %11 = add i64 %10, %2, !insn.addr !27
  %12 = sub i64 %11, %4, !insn.addr !28
  %13 = add i64 %12, %8, !insn.addr !29
  %14 = and i64 %13, 4294967295, !insn.addr !30
  ret i64 %14, !insn.addr !31

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_27c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !32
  %3 = call i64 @f_scanf_nop(), !insn.addr !33
  %4 = call i64 @f_rand(), !insn.addr !34
  %5 = call i64 @f_rand(), !insn.addr !35
  %6 = call i64 @f_rand(), !insn.addr !36
  %7 = call i64 @f_printf(), !insn.addr !37
  %8 = call i64 @f_printf(), !insn.addr !38
  %9 = call i64 @f_printf(), !insn.addr !39
  %10 = sub i64 770, %1, !insn.addr !40
  %11 = and i64 %10, 4294967295, !insn.addr !41
  ret i64 %11, !insn.addr !42

; uselistorder directives
  uselistorder i32 1, { 2, 1, 0 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_368:
  %0 = call i64 @f_rand(), !insn.addr !43
  %1 = call i64 @f_rand(), !insn.addr !44
  %2 = call i64 @f_rand(), !insn.addr !45
  %3 = call i64 @f_rand(), !insn.addr !46
  %4 = call i64 @f_scanf_nop(), !insn.addr !47
  %5 = call i64 @f_printf(), !insn.addr !48
  %6 = call i64 @f_printf(), !insn.addr !49
  %7 = call i64 @f_printf(), !insn.addr !50
  %8 = call i64 @f_printf(), !insn.addr !51
  %9 = call i64 @f_printf(), !insn.addr !52
  %10 = sub i64 %2, %3, !insn.addr !53
  %11 = and i64 %10, 4294967295, !insn.addr !54
  ret i64 %11, !insn.addr !55
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_490:
  %0 = call i64 @f_rand(), !insn.addr !56
  %1 = call i64 @f_rand(), !insn.addr !57
  %2 = call i64 @f_scanf_nop(), !insn.addr !58
  %3 = call i64 @f_scanf_nop(), !insn.addr !59
  %4 = call i64 @f_scanf_nop(), !insn.addr !60
  %5 = call i64 @f_printf(), !insn.addr !61
  %6 = call i64 @f_printf(), !insn.addr !62
  %7 = sub i64 4294966620, %0, !insn.addr !63
  %8 = add i64 %7, %1, !insn.addr !64
  %9 = sub i64 %8, %2, !insn.addr !65
  %10 = add i64 %9, %4, !insn.addr !66
  %11 = and i64 %10, 4294967295, !insn.addr !67
  ret i64 %11, !insn.addr !68

; uselistorder directives
  uselistorder i64 4294967295, { 1, 2, 3, 4, 5, 0 }
  uselistorder i64 ()* @f_printf, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_58c:
  %0 = call i64 @f_scanf_nop(), !insn.addr !69
  %1 = call i64 @f_scanf_nop(), !insn.addr !70
  %2 = call i64 @f_rand(), !insn.addr !71
  %3 = call i64 @f_scanf_nop(), !insn.addr !72
  %4 = call i64 @func0(), !insn.addr !73
  %5 = call i64 @func1(), !insn.addr !74
  %6 = call i64 @func2(), !insn.addr !75
  %7 = call i64 @func3(), !insn.addr !76
  %8 = call i64 @func4(), !insn.addr !77
  ret i64 0, !insn.addr !78

; uselistorder directives
  uselistorder i64 ()* @f_rand, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_scanf_nop, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 28}
!1 = !{i64 68}
!2 = !{i64 104}
!3 = !{i64 120}
!4 = !{i64 124}
!5 = !{i64 136}
!6 = !{i64 168}
!7 = !{i64 176}
!8 = !{i64 184}
!9 = !{i64 192}
!10 = !{i64 200}
!11 = !{i64 232}
!12 = !{i64 316}
!13 = !{i64 328}
!14 = !{i64 336}
!15 = !{i64 348}
!16 = !{i64 388}
!17 = !{i64 396}
!18 = !{i64 404}
!19 = !{i64 412}
!20 = !{i64 420}
!21 = !{i64 496}
!22 = !{i64 528}
!23 = !{i64 540}
!24 = !{i64 548}
!25 = !{i64 576}
!26 = !{i64 564}
!27 = !{i64 588}
!28 = !{i64 596}
!29 = !{i64 612}
!30 = !{i64 620}
!31 = !{i64 632}
!32 = !{i64 672}
!33 = !{i64 680}
!34 = !{i64 688}
!35 = !{i64 696}
!36 = !{i64 704}
!37 = !{i64 748}
!38 = !{i64 780}
!39 = !{i64 804}
!40 = !{i64 848}
!41 = !{i64 856}
!42 = !{i64 868}
!43 = !{i64 912}
!44 = !{i64 920}
!45 = !{i64 928}
!46 = !{i64 936}
!47 = !{i64 944}
!48 = !{i64 988}
!49 = !{i64 1012}
!50 = !{i64 1052}
!51 = !{i64 1108}
!52 = !{i64 1132}
!53 = !{i64 1144}
!54 = !{i64 1152}
!55 = !{i64 1164}
!56 = !{i64 1196}
!57 = !{i64 1204}
!58 = !{i64 1212}
!59 = !{i64 1220}
!60 = !{i64 1228}
!61 = !{i64 1328}
!62 = !{i64 1352}
!63 = !{i64 1260}
!64 = !{i64 1268}
!65 = !{i64 1276}
!66 = !{i64 1396}
!67 = !{i64 1404}
!68 = !{i64 1416}
!69 = !{i64 1444}
!70 = !{i64 1452}
!71 = !{i64 1460}
!72 = !{i64 1468}
!73 = !{i64 1476}
!74 = !{i64 1492}
!75 = !{i64 1508}
!76 = !{i64 1528}
!77 = !{i64 1532}
!78 = !{i64 1552}
