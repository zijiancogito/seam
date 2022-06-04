source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

define i64 @function_0() local_unnamed_addr {
dec_label_pc_0:
  ret i64 0, !insn.addr !0
}

define i64 @function_30() local_unnamed_addr {
dec_label_pc_30:
  %0 = alloca i32
  %1 = load i32, i32* %0
  %2 = zext i32 %1 to i64, !insn.addr !1
  ret i64 %2, !insn.addr !2
}

define i64 @function_60() local_unnamed_addr {
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

define i64 @function_8c() local_unnamed_addr {
dec_label_pc_8c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_60(), !insn.addr !7
  %3 = call i64 @function_30(), !insn.addr !8
  %4 = call i64 @function_60(), !insn.addr !9
  %5 = call i64 @function_60(), !insn.addr !10
  %6 = call i64 @function_60(), !insn.addr !11
  %7 = call i64 @function_0(), !insn.addr !12
  %8 = add i64 %2, %1, !insn.addr !13
  %9 = add i64 %8, %6, !insn.addr !14
  %10 = mul i64 %9, %3, !insn.addr !15
  %11 = sub i64 %1, %3, !insn.addr !16
  %12 = add i64 %11, %10, !insn.addr !17
  %13 = call i64 @function_0(), !insn.addr !18
  %14 = call i64 @function_0(), !insn.addr !19
  %15 = mul i64 %12, %4, !insn.addr !20
  %16 = and i64 %15, 4294967295, !insn.addr !21
  ret i64 %16, !insn.addr !22

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @function_190() local_unnamed_addr {
dec_label_pc_190:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = trunc i64 %1 to i32, !insn.addr !23
  %3 = call i64 @function_30(), !insn.addr !24
  %4 = trunc i64 %3 to i32, !insn.addr !25
  %5 = call i64 @function_30(), !insn.addr !26
  %6 = trunc i64 %5 to i32, !insn.addr !27
  %7 = call i64 @function_60(), !insn.addr !28
  %8 = trunc i64 %7 to i32, !insn.addr !29
  %9 = call i64 @function_60(), !insn.addr !30
  %10 = call i64 @function_60(), !insn.addr !31
  %11 = trunc i64 %10 to i32, !insn.addr !32
  %12 = mul i32 %8, %4, !insn.addr !33
  %13 = add i32 %12, %6, !insn.addr !34
  %14 = call i64 @function_0(), !insn.addr !35
  %15 = add i32 %8, %6, !insn.addr !36
  %16 = add i32 %15, %11, !insn.addr !37
  %17 = call i64 @function_0(), !insn.addr !38
  %18 = mul i32 %16, %11
  %19 = mul i32 %13, %4, !insn.addr !39
  %20 = add i32 %4, %2, !insn.addr !40
  %21 = add i32 %20, %13, !insn.addr !41
  %22 = mul i32 %21, %2, !insn.addr !42
  %23 = call i64 @function_0(), !insn.addr !43
  %24 = sub i32 %12, %19
  %25 = mul i32 %18, %24, !insn.addr !44
  %26 = mul i32 %25, %12, !insn.addr !45
  %27 = sub i32 %22, %13, !insn.addr !46
  %28 = add i32 %27, %26, !insn.addr !47
  %29 = zext i32 %28 to i64, !insn.addr !48
  ret i64 %29, !insn.addr !49

; uselistorder directives
  uselistorder i32 %13, { 0, 2, 1 }
  uselistorder i32 %12, { 1, 0, 2 }
}

define i64 @function_2d8() local_unnamed_addr {
dec_label_pc_2d8:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = trunc i64 %2 to i32, !insn.addr !50
  %4 = trunc i64 %1 to i32, !insn.addr !51
  %5 = call i64 @function_30(), !insn.addr !52
  %6 = call i64 @function_60(), !insn.addr !53
  %7 = call i64 @function_60(), !insn.addr !54
  %8 = trunc i64 %7 to i32, !insn.addr !55
  %9 = call i64 @function_60(), !insn.addr !56
  %10 = trunc i64 %9 to i32, !insn.addr !57
  %11 = call i64 @function_60(), !insn.addr !58
  %12 = add i32 %8, 508, !insn.addr !59
  %13 = call i64 @function_0(), !insn.addr !60
  %14 = sub i32 %3, %8, !insn.addr !61
  %15 = sub i32 %14, %10, !insn.addr !62
  %16 = add i32 %4, 583, !insn.addr !63
  %17 = mul i32 %16, %3, !insn.addr !64
  %18 = mul i32 %17, %12, !insn.addr !65
  %19 = add i32 %18, %12, !insn.addr !66
  %20 = mul i32 %19, %18, !insn.addr !67
  %21 = add i32 %15, %20, !insn.addr !68
  %22 = zext i32 %21 to i64, !insn.addr !69
  ret i64 %22, !insn.addr !70

; uselistorder directives
  uselistorder i32 %3, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
  uselistorder i32 1, { 4, 3, 2, 1, 0, 5 }
}

define i64 @function_3cc() local_unnamed_addr {
dec_label_pc_3cc:
  %0 = call i64 @function_30(), !insn.addr !71
  %1 = call i64 @function_60(), !insn.addr !72
  %2 = call i64 @function_30(), !insn.addr !73
  %3 = call i64 @function_60(), !insn.addr !74
  %4 = call i64 @function_60(), !insn.addr !75
  %5 = sub i64 498, %4, !insn.addr !76
  %6 = and i64 %5, 4294967295, !insn.addr !77
  ret i64 %6, !insn.addr !78
}

define i64 @function_498() local_unnamed_addr {
dec_label_pc_498:
  %0 = call i64 @function_30(), !insn.addr !79
  %1 = call i64 @function_30(), !insn.addr !80
  %2 = call i64 @function_30(), !insn.addr !81
  %3 = call i64 @function_30(), !insn.addr !82
  %4 = call i64 @function_60(), !insn.addr !83
  %5 = call i64 @function_0(), !insn.addr !84
  %6 = call i64 @function_0(), !insn.addr !85
  %7 = mul i64 %1, 4294959443, !insn.addr !86
  %8 = and i64 %7, 4294967295, !insn.addr !87
  ret i64 %8, !insn.addr !88

; uselistorder directives
  uselistorder i64 4294967295, { 1, 2, 3, 0 }
  uselistorder i64 ()* @function_0, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @function_588() local_unnamed_addr {
dec_label_pc_588:
  %0 = call i64 @function_30(), !insn.addr !89
  %1 = call i64 @function_60(), !insn.addr !90
  %2 = call i64 @function_30(), !insn.addr !91
  %3 = call i64 @function_60(), !insn.addr !92
  %4 = call i64 @function_8c(), !insn.addr !93
  %5 = call i64 @function_190(), !insn.addr !94
  %6 = call i64 @function_2d8(), !insn.addr !95
  %7 = call i64 @function_3cc(), !insn.addr !96
  %8 = call i64 @function_498(), !insn.addr !97
  ret i64 0, !insn.addr !98

; uselistorder directives
  uselistorder i64 ()* @function_60, { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @function_30, { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 44}
!1 = !{i64 80}
!2 = !{i64 92}
!3 = !{i64 116}
!4 = !{i64 120}
!5 = !{i64 124}
!6 = !{i64 136}
!7 = !{i64 176}
!8 = !{i64 184}
!9 = !{i64 192}
!10 = !{i64 200}
!11 = !{i64 208}
!12 = !{i64 252}
!13 = !{i64 264}
!14 = !{i64 272}
!15 = !{i64 280}
!16 = !{i64 288}
!17 = !{i64 296}
!18 = !{i64 324}
!19 = !{i64 364}
!20 = !{i64 376}
!21 = !{i64 384}
!22 = !{i64 396}
!23 = !{i64 420}
!24 = !{i64 432}
!25 = !{i64 436}
!26 = !{i64 440}
!27 = !{i64 444}
!28 = !{i64 448}
!29 = !{i64 452}
!30 = !{i64 456}
!31 = !{i64 464}
!32 = !{i64 468}
!33 = !{i64 496}
!34 = !{i64 512}
!35 = !{i64 524}
!36 = !{i64 536}
!37 = !{i64 544}
!38 = !{i64 556}
!39 = !{i64 576}
!40 = !{i64 624}
!41 = !{i64 632}
!42 = !{i64 640}
!43 = !{i64 652}
!44 = !{i64 680}
!45 = !{i64 688}
!46 = !{i64 696}
!47 = !{i64 704}
!48 = !{i64 712}
!49 = !{i64 724}
!50 = !{i64 748}
!51 = !{i64 752}
!52 = !{i64 764}
!53 = !{i64 772}
!54 = !{i64 780}
!55 = !{i64 784}
!56 = !{i64 788}
!57 = !{i64 792}
!58 = !{i64 796}
!59 = !{i64 828}
!60 = !{i64 840}
!61 = !{i64 852}
!62 = !{i64 860}
!63 = !{i64 876}
!64 = !{i64 884}
!65 = !{i64 892}
!66 = !{i64 908}
!67 = !{i64 940}
!68 = !{i64 948}
!69 = !{i64 956}
!70 = !{i64 968}
!71 = !{i64 1000}
!72 = !{i64 1008}
!73 = !{i64 1016}
!74 = !{i64 1024}
!75 = !{i64 1032}
!76 = !{i64 1152}
!77 = !{i64 1160}
!78 = !{i64 1172}
!79 = !{i64 1208}
!80 = !{i64 1216}
!81 = !{i64 1224}
!82 = !{i64 1232}
!83 = !{i64 1240}
!84 = !{i64 1284}
!85 = !{i64 1332}
!86 = !{i64 1392}
!87 = !{i64 1400}
!88 = !{i64 1412}
!89 = !{i64 1440}
!90 = !{i64 1448}
!91 = !{i64 1456}
!92 = !{i64 1464}
!93 = !{i64 1480}
!94 = !{i64 1492}
!95 = !{i64 1508}
!96 = !{i64 1512}
!97 = !{i64 1524}
!98 = !{i64 1544}
