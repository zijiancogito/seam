source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@global_var_6c = local_unnamed_addr constant i64 -7995600141899792376

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, 616, !insn.addr !0
  ret i64 %2, !insn.addr !1
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_30:
  ret i64 616, !insn.addr !2
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
  %2 = load i64, i64* %0
  %3 = call i64 @f_scanf_nop(), !insn.addr !7
  %4 = call i64 @f_scanf_nop(), !insn.addr !8
  %5 = call i64 @f_rand(), !insn.addr !9
  %6 = call i64 @f_scanf_nop(), !insn.addr !10
  %7 = call i64 @f_rand(), !insn.addr !11
  %factor = mul i64 %2, 2
  %8 = sub i64 %factor, %1, !insn.addr !12
  %9 = sub i64 %8, %5, !insn.addr !13
  %10 = mul i64 %9, 700
  %11 = add i64 %7, %6, !insn.addr !14
  %12 = add i64 %11, %10, !insn.addr !15
  %13 = mul i64 %12, %7, !insn.addr !16
  %14 = add i64 %13, %6, !insn.addr !17
  %15 = and i64 %14, 4294967295, !insn.addr !18
  ret i64 %15, !insn.addr !19

; uselistorder directives
  uselistorder i64* %0, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_1a0:
  %0 = call i64 @f_scanf_nop(), !insn.addr !20
  %1 = call i64 @f_rand(), !insn.addr !21
  %2 = call i64 @f_scanf_nop(), !insn.addr !22
  %3 = call i64 @f_scanf_nop(), !insn.addr !23
  %4 = call i64 @f_scanf_nop(), !insn.addr !24
  %5 = call i64 @f_printf(), !insn.addr !25
  %6 = call i64 @f_printf(), !insn.addr !26
  %7 = add i64 %0, 233, !insn.addr !27
  %8 = and i64 %7, 4294967295, !insn.addr !28
  ret i64 %8, !insn.addr !29
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_294:
  %0 = call i64 @f_rand(), !insn.addr !30
  %1 = call i64 @f_rand(), !insn.addr !31
  %2 = call i64 @f_scanf_nop(), !insn.addr !32
  %3 = call i64 @f_scanf_nop(), !insn.addr !33
  %4 = call i64 @f_rand(), !insn.addr !34
  %5 = call i64 @f_printf(), !insn.addr !35
  %6 = add i64 %1, 4294966677, !insn.addr !36
  %7 = mul i64 %3, %6, !insn.addr !37
  %8 = call i64 @f_printf(), !insn.addr !38
  %9 = mul i64 %0, -4294966677, !insn.addr !39
  %.neg1 = mul i64 %9, %2
  %.neg2 = sub i64 %2, %1, !insn.addr !40
  %10 = add i64 %.neg2, %.neg1, !insn.addr !41
  %11 = mul i64 %10, %1, !insn.addr !42
  %12 = add i64 %11, %7, !insn.addr !43
  %13 = and i64 %12, 4294967295, !insn.addr !44
  ret i64 %13, !insn.addr !45

; uselistorder directives
  uselistorder i64 %1, { 1, 0, 2 }
  uselistorder i64 4294967295, { 1, 2, 3, 0 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_3a4:
  %0 = call i64 @f_rand(), !insn.addr !46
  %1 = trunc i64 %0 to i32, !insn.addr !47
  %2 = call i64 @f_scanf_nop(), !insn.addr !48
  %3 = call i64 @f_rand(), !insn.addr !49
  %4 = call i64 @f_rand(), !insn.addr !50
  %5 = trunc i64 %4 to i32, !insn.addr !51
  %6 = call i64 @f_rand(), !insn.addr !52
  %7 = trunc i64 %6 to i32, !insn.addr !53
  %8 = mul i32 %1, 737, !insn.addr !54
  %9 = add i32 %8, %5, !insn.addr !55
  %10 = call i64 @f_printf(), !insn.addr !56
  %11 = call i64 @f_printf(), !insn.addr !57
  %12 = call i64 @f_printf(), !insn.addr !58
  %13 = mul i32 %9, %1, !insn.addr !59
  %14 = sub i32 %9, %7, !insn.addr !60
  %15 = add i32 %14, %13, !insn.addr !61
  %16 = mul i32 %7, -94, !insn.addr !62
  %17 = mul i32 %16, %15, !insn.addr !63
  %18 = add i32 %17, %7, !insn.addr !64
  %19 = zext i32 %18 to i64, !insn.addr !65
  ret i64 %19, !insn.addr !66

; uselistorder directives
  uselistorder i32 %7, { 1, 2, 0 }
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_4bc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = trunc i64 %1 to i32, !insn.addr !67
  %3 = call i64 @f_rand(), !insn.addr !68
  %4 = call i64 @f_rand(), !insn.addr !69
  %5 = trunc i64 %4 to i32, !insn.addr !70
  %6 = call i64 @f_scanf_nop(), !insn.addr !71
  %7 = trunc i64 %6 to i32, !insn.addr !72
  %8 = call i64 @f_scanf_nop(), !insn.addr !73
  %9 = trunc i64 %8 to i32, !insn.addr !74
  %10 = call i64 @f_rand(), !insn.addr !75
  %11 = sub i32 %5, %2, !insn.addr !76
  %12 = call i64 @f_printf(), !insn.addr !77
  %13 = add i32 %11, -849, !insn.addr !78
  %14 = mul i32 %13, %9, !insn.addr !79
  %15 = call i64 @f_printf(), !insn.addr !80
  %16 = add i32 %7, %2
  %17 = sub i32 %11, %16, !insn.addr !81
  %18 = add i32 %17, %9, !insn.addr !82
  %19 = add i32 %18, %14, !insn.addr !83
  %20 = zext i32 %19 to i64, !insn.addr !84
  ret i64 %20, !insn.addr !85

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_rand, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_5d4:
  %0 = call i64 @f_scanf_nop(), !insn.addr !86
  %1 = call i64 @f_scanf_nop(), !insn.addr !87
  %2 = call i64 @f_scanf_nop(), !insn.addr !88
  %3 = call i64 @f_scanf_nop(), !insn.addr !89
  %4 = call i64 @func0(), !insn.addr !90
  %5 = call i64 @func1(), !insn.addr !91
  %6 = call i64 @func2(), !insn.addr !92
  %7 = call i64 @func3(), !insn.addr !93
  %8 = call i64 @func4(), !insn.addr !94
  ret i64 0, !insn.addr !95

; uselistorder directives
  uselistorder i64 ()* @f_scanf_nop, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @"$d.1"() local_unnamed_addr {
dec_label_pc_668:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1
}

define i64 @function_670() local_unnamed_addr {
dec_label_pc_670:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1

; uselistorder directives
  uselistorder i32 1, { 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 16}
!1 = !{i64 28}
!2 = !{i64 68}
!3 = !{i64 104}
!4 = !{i64 120}
!5 = !{i64 124}
!6 = !{i64 136}
!7 = !{i64 176}
!8 = !{i64 184}
!9 = !{i64 192}
!10 = !{i64 200}
!11 = !{i64 208}
!12 = !{i64 272}
!13 = !{i64 280}
!14 = !{i64 368}
!15 = !{i64 376}
!16 = !{i64 384}
!17 = !{i64 392}
!18 = !{i64 400}
!19 = !{i64 412}
!20 = !{i64 452}
!21 = !{i64 460}
!22 = !{i64 468}
!23 = !{i64 476}
!24 = !{i64 484}
!25 = !{i64 584}
!26 = !{i64 608}
!27 = !{i64 636}
!28 = !{i64 644}
!29 = !{i64 656}
!30 = !{i64 692}
!31 = !{i64 700}
!32 = !{i64 708}
!33 = !{i64 716}
!34 = !{i64 724}
!35 = !{i64 784}
!36 = !{i64 796}
!37 = !{i64 804}
!38 = !{i64 840}
!39 = !{i64 764}
!40 = !{i64 772}
!41 = !{i64 852}
!42 = !{i64 860}
!43 = !{i64 908}
!44 = !{i64 916}
!45 = !{i64 928}
!46 = !{i64 964}
!47 = !{i64 968}
!48 = !{i64 972}
!49 = !{i64 980}
!50 = !{i64 988}
!51 = !{i64 992}
!52 = !{i64 996}
!53 = !{i64 1000}
!54 = !{i64 1028}
!55 = !{i64 1036}
!56 = !{i64 1048}
!57 = !{i64 1072}
!58 = !{i64 1096}
!59 = !{i64 1140}
!60 = !{i64 1148}
!61 = !{i64 1156}
!62 = !{i64 1172}
!63 = !{i64 1180}
!64 = !{i64 1188}
!65 = !{i64 1196}
!66 = !{i64 1208}
!67 = !{i64 1240}
!68 = !{i64 1252}
!69 = !{i64 1260}
!70 = !{i64 1264}
!71 = !{i64 1268}
!72 = !{i64 1272}
!73 = !{i64 1276}
!74 = !{i64 1280}
!75 = !{i64 1284}
!76 = !{i64 1316}
!77 = !{i64 1328}
!78 = !{i64 1364}
!79 = !{i64 1372}
!80 = !{i64 1456}
!81 = !{i64 1388}
!82 = !{i64 1396}
!83 = !{i64 1468}
!84 = !{i64 1476}
!85 = !{i64 1488}
!86 = !{i64 1516}
!87 = !{i64 1524}
!88 = !{i64 1532}
!89 = !{i64 1540}
!90 = !{i64 1556}
!91 = !{i64 1572}
!92 = !{i64 1584}
!93 = !{i64 1596}
!94 = !{i64 1616}
!95 = !{i64 1636}
