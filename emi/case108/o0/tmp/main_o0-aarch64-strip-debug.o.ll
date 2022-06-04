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
  %8 = add i64 %2, %1, !insn.addr !12
  %9 = add i64 %8, %6, !insn.addr !13
  %10 = mul i64 %9, %3, !insn.addr !14
  %11 = sub i64 %1, %3, !insn.addr !15
  %12 = add i64 %11, %10, !insn.addr !16
  %13 = call i64 @f_printf(), !insn.addr !17
  %14 = call i64 @f_printf(), !insn.addr !18
  %15 = mul i64 %12, %4, !insn.addr !19
  %16 = and i64 %15, 4294967295, !insn.addr !20
  ret i64 %16, !insn.addr !21

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_190:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = trunc i64 %1 to i32, !insn.addr !22
  %3 = call i64 @f_scanf_nop(), !insn.addr !23
  %4 = trunc i64 %3 to i32, !insn.addr !24
  %5 = call i64 @f_scanf_nop(), !insn.addr !25
  %6 = trunc i64 %5 to i32, !insn.addr !26
  %7 = call i64 @f_rand(), !insn.addr !27
  %8 = trunc i64 %7 to i32, !insn.addr !28
  %9 = call i64 @f_rand(), !insn.addr !29
  %10 = call i64 @f_rand(), !insn.addr !30
  %11 = trunc i64 %10 to i32, !insn.addr !31
  %12 = mul i32 %8, %4, !insn.addr !32
  %13 = add i32 %12, %6, !insn.addr !33
  %14 = call i64 @f_printf(), !insn.addr !34
  %15 = add i32 %8, %6, !insn.addr !35
  %16 = add i32 %15, %11, !insn.addr !36
  %17 = call i64 @f_printf(), !insn.addr !37
  %18 = mul i32 %16, %11
  %19 = mul i32 %13, %4, !insn.addr !38
  %20 = add i32 %4, %2, !insn.addr !39
  %21 = add i32 %20, %13, !insn.addr !40
  %22 = mul i32 %21, %2, !insn.addr !41
  %23 = call i64 @f_printf(), !insn.addr !42
  %24 = sub i32 %12, %19
  %25 = mul i32 %18, %24, !insn.addr !43
  %26 = mul i32 %25, %12, !insn.addr !44
  %27 = sub i32 %22, %13, !insn.addr !45
  %28 = add i32 %27, %26, !insn.addr !46
  %29 = zext i32 %28 to i64, !insn.addr !47
  ret i64 %29, !insn.addr !48

; uselistorder directives
  uselistorder i32 %13, { 0, 2, 1 }
  uselistorder i32 %12, { 1, 0, 2 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_2d8:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = trunc i64 %2 to i32, !insn.addr !49
  %4 = trunc i64 %1 to i32, !insn.addr !50
  %5 = call i64 @f_scanf_nop(), !insn.addr !51
  %6 = call i64 @f_rand(), !insn.addr !52
  %7 = call i64 @f_rand(), !insn.addr !53
  %8 = trunc i64 %7 to i32, !insn.addr !54
  %9 = call i64 @f_rand(), !insn.addr !55
  %10 = trunc i64 %9 to i32, !insn.addr !56
  %11 = call i64 @f_rand(), !insn.addr !57
  %12 = add i32 %8, 508, !insn.addr !58
  %13 = call i64 @f_printf(), !insn.addr !59
  %14 = sub i32 %3, %8, !insn.addr !60
  %15 = sub i32 %14, %10, !insn.addr !61
  %16 = add i32 %4, 583, !insn.addr !62
  %17 = mul i32 %16, %3, !insn.addr !63
  %18 = mul i32 %17, %12, !insn.addr !64
  %19 = add i32 %18, %12, !insn.addr !65
  %20 = mul i32 %19, %18, !insn.addr !66
  %21 = add i32 %15, %20, !insn.addr !67
  %22 = zext i32 %21 to i64, !insn.addr !68
  ret i64 %22, !insn.addr !69

; uselistorder directives
  uselistorder i32 %3, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
  uselistorder i32 1, { 4, 3, 2, 1, 0 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_3cc:
  %0 = call i64 @f_scanf_nop(), !insn.addr !70
  %1 = call i64 @f_rand(), !insn.addr !71
  %2 = call i64 @f_scanf_nop(), !insn.addr !72
  %3 = call i64 @f_rand(), !insn.addr !73
  %4 = call i64 @f_rand(), !insn.addr !74
  %5 = sub i64 498, %4, !insn.addr !75
  %6 = and i64 %5, 4294967295, !insn.addr !76
  ret i64 %6, !insn.addr !77
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_498:
  %0 = call i64 @f_scanf_nop(), !insn.addr !78
  %1 = call i64 @f_scanf_nop(), !insn.addr !79
  %2 = call i64 @f_scanf_nop(), !insn.addr !80
  %3 = call i64 @f_scanf_nop(), !insn.addr !81
  %4 = call i64 @f_rand(), !insn.addr !82
  %5 = call i64 @f_printf(), !insn.addr !83
  %6 = call i64 @f_printf(), !insn.addr !84
  %7 = mul i64 %1, 4294959443, !insn.addr !85
  %8 = and i64 %7, 4294967295, !insn.addr !86
  ret i64 %8, !insn.addr !87

; uselistorder directives
  uselistorder i64 4294967295, { 1, 2, 3, 0 }
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_588:
  %0 = call i64 @f_scanf_nop(), !insn.addr !88
  %1 = call i64 @f_rand(), !insn.addr !89
  %2 = call i64 @f_scanf_nop(), !insn.addr !90
  %3 = call i64 @f_rand(), !insn.addr !91
  %4 = call i64 @func0(), !insn.addr !92
  %5 = call i64 @func1(), !insn.addr !93
  %6 = call i64 @func2(), !insn.addr !94
  %7 = call i64 @func3(), !insn.addr !95
  %8 = call i64 @func4(), !insn.addr !96
  ret i64 0, !insn.addr !97

; uselistorder directives
  uselistorder i64 ()* @f_rand, { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_scanf_nop, { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 28}
!1 = !{i64 68}
!2 = !{i64 104}
!3 = !{i64 120}
!4 = !{i64 124}
!5 = !{i64 136}
!6 = !{i64 176}
!7 = !{i64 184}
!8 = !{i64 192}
!9 = !{i64 200}
!10 = !{i64 208}
!11 = !{i64 252}
!12 = !{i64 264}
!13 = !{i64 272}
!14 = !{i64 280}
!15 = !{i64 288}
!16 = !{i64 296}
!17 = !{i64 324}
!18 = !{i64 364}
!19 = !{i64 376}
!20 = !{i64 384}
!21 = !{i64 396}
!22 = !{i64 420}
!23 = !{i64 432}
!24 = !{i64 436}
!25 = !{i64 440}
!26 = !{i64 444}
!27 = !{i64 448}
!28 = !{i64 452}
!29 = !{i64 456}
!30 = !{i64 464}
!31 = !{i64 468}
!32 = !{i64 496}
!33 = !{i64 512}
!34 = !{i64 524}
!35 = !{i64 536}
!36 = !{i64 544}
!37 = !{i64 556}
!38 = !{i64 576}
!39 = !{i64 624}
!40 = !{i64 632}
!41 = !{i64 640}
!42 = !{i64 652}
!43 = !{i64 680}
!44 = !{i64 688}
!45 = !{i64 696}
!46 = !{i64 704}
!47 = !{i64 712}
!48 = !{i64 724}
!49 = !{i64 748}
!50 = !{i64 752}
!51 = !{i64 764}
!52 = !{i64 772}
!53 = !{i64 780}
!54 = !{i64 784}
!55 = !{i64 788}
!56 = !{i64 792}
!57 = !{i64 796}
!58 = !{i64 828}
!59 = !{i64 840}
!60 = !{i64 852}
!61 = !{i64 860}
!62 = !{i64 876}
!63 = !{i64 884}
!64 = !{i64 892}
!65 = !{i64 908}
!66 = !{i64 940}
!67 = !{i64 948}
!68 = !{i64 956}
!69 = !{i64 968}
!70 = !{i64 1000}
!71 = !{i64 1008}
!72 = !{i64 1016}
!73 = !{i64 1024}
!74 = !{i64 1032}
!75 = !{i64 1152}
!76 = !{i64 1160}
!77 = !{i64 1172}
!78 = !{i64 1208}
!79 = !{i64 1216}
!80 = !{i64 1224}
!81 = !{i64 1232}
!82 = !{i64 1240}
!83 = !{i64 1284}
!84 = !{i64 1332}
!85 = !{i64 1392}
!86 = !{i64 1400}
!87 = !{i64 1412}
!88 = !{i64 1440}
!89 = !{i64 1448}
!90 = !{i64 1456}
!91 = !{i64 1464}
!92 = !{i64 1480}
!93 = !{i64 1492}
!94 = !{i64 1508}
!95 = !{i64 1512}
!96 = !{i64 1524}
!97 = !{i64 1544}
