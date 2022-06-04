source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@global_var_6c = local_unnamed_addr constant i64 -7998391801922715640

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
  %2 = load i64, i64* %0
  %3 = call i64 @f_scanf_nop(), !insn.addr !6
  %4 = call i64 @f_scanf_nop(), !insn.addr !7
  %5 = call i64 @f_rand(), !insn.addr !8
  %6 = call i64 @f_scanf_nop(), !insn.addr !9
  %7 = call i64 @f_rand(), !insn.addr !10
  %factor = mul i64 %2, 2
  %8 = sub i64 %factor, %1, !insn.addr !11
  %9 = sub i64 %8, %5, !insn.addr !12
  %10 = mul i64 %9, 700
  %11 = add i64 %7, %6, !insn.addr !13
  %12 = add i64 %11, %10, !insn.addr !14
  %13 = mul i64 %12, %7, !insn.addr !15
  %14 = add i64 %13, %6, !insn.addr !16
  %15 = and i64 %14, 4294967295, !insn.addr !17
  ret i64 %15, !insn.addr !18

; uselistorder directives
  uselistorder i64* %0, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_1a0:
  %0 = call i64 @f_scanf_nop(), !insn.addr !19
  %1 = call i64 @f_rand(), !insn.addr !20
  %2 = call i64 @f_scanf_nop(), !insn.addr !21
  %3 = call i64 @f_scanf_nop(), !insn.addr !22
  %4 = call i64 @f_scanf_nop(), !insn.addr !23
  %5 = call i64 @f_printf(), !insn.addr !24
  %6 = call i64 @f_printf(), !insn.addr !25
  %7 = add i64 %0, 233, !insn.addr !26
  %8 = and i64 %7, 4294967295, !insn.addr !27
  ret i64 %8, !insn.addr !28
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_294:
  %0 = call i64 @f_rand(), !insn.addr !29
  %1 = call i64 @f_rand(), !insn.addr !30
  %2 = call i64 @f_scanf_nop(), !insn.addr !31
  %3 = call i64 @f_scanf_nop(), !insn.addr !32
  %4 = call i64 @f_rand(), !insn.addr !33
  %5 = call i64 @f_printf(), !insn.addr !34
  %6 = add i64 %1, 4294966677, !insn.addr !35
  %7 = mul i64 %3, %6, !insn.addr !36
  %8 = call i64 @f_printf(), !insn.addr !37
  %9 = mul i64 %0, -4294966677, !insn.addr !38
  %.neg1 = mul i64 %9, %2
  %.neg2 = sub i64 %2, %1, !insn.addr !39
  %10 = add i64 %.neg2, %.neg1, !insn.addr !40
  %11 = mul i64 %10, %1, !insn.addr !41
  %12 = add i64 %11, %7, !insn.addr !42
  %13 = and i64 %12, 4294967295, !insn.addr !43
  ret i64 %13, !insn.addr !44

; uselistorder directives
  uselistorder i64 %1, { 1, 0, 2 }
  uselistorder i64 4294967295, { 1, 2, 3, 0 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_3a4:
  %0 = call i64 @f_rand(), !insn.addr !45
  %1 = trunc i64 %0 to i32, !insn.addr !46
  %2 = call i64 @f_scanf_nop(), !insn.addr !47
  %3 = call i64 @f_rand(), !insn.addr !48
  %4 = call i64 @f_rand(), !insn.addr !49
  %5 = trunc i64 %4 to i32, !insn.addr !50
  %6 = call i64 @f_rand(), !insn.addr !51
  %7 = trunc i64 %6 to i32, !insn.addr !52
  %8 = mul i32 %1, 737, !insn.addr !53
  %9 = add i32 %8, %5, !insn.addr !54
  %10 = call i64 @f_printf(), !insn.addr !55
  %11 = call i64 @f_printf(), !insn.addr !56
  %12 = call i64 @f_printf(), !insn.addr !57
  %13 = mul i32 %9, %1, !insn.addr !58
  %14 = sub i32 %9, %7, !insn.addr !59
  %15 = add i32 %14, %13, !insn.addr !60
  %16 = mul i32 %7, -94, !insn.addr !61
  %17 = mul i32 %16, %15, !insn.addr !62
  %18 = add i32 %17, %7, !insn.addr !63
  %19 = zext i32 %18 to i64, !insn.addr !64
  ret i64 %19, !insn.addr !65

; uselistorder directives
  uselistorder i32 %7, { 1, 2, 0 }
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_4bc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = trunc i64 %1 to i32, !insn.addr !66
  %3 = call i64 @f_rand(), !insn.addr !67
  %4 = call i64 @f_rand(), !insn.addr !68
  %5 = trunc i64 %4 to i32, !insn.addr !69
  %6 = call i64 @f_scanf_nop(), !insn.addr !70
  %7 = trunc i64 %6 to i32, !insn.addr !71
  %8 = call i64 @f_scanf_nop(), !insn.addr !72
  %9 = trunc i64 %8 to i32, !insn.addr !73
  %10 = call i64 @f_rand(), !insn.addr !74
  %11 = sub i32 %5, %2, !insn.addr !75
  %12 = call i64 @f_printf(), !insn.addr !76
  %13 = add i32 %11, -849, !insn.addr !77
  %14 = mul i32 %13, %9, !insn.addr !78
  %15 = call i64 @f_printf(), !insn.addr !79
  %16 = add i32 %7, %2
  %17 = sub i32 %11, %16, !insn.addr !80
  %18 = add i32 %17, %9, !insn.addr !81
  %19 = add i32 %18, %14, !insn.addr !82
  %20 = zext i32 %19 to i64, !insn.addr !83
  ret i64 %20, !insn.addr !84

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_rand, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i32 1, { 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_5d4:
  %0 = call i64 @f_scanf_nop(), !insn.addr !85
  %1 = call i64 @f_scanf_nop(), !insn.addr !86
  %2 = call i64 @f_scanf_nop(), !insn.addr !87
  %3 = call i64 @f_scanf_nop(), !insn.addr !88
  %4 = call i64 @func0(), !insn.addr !89
  %5 = call i64 @func1(), !insn.addr !90
  %6 = call i64 @func2(), !insn.addr !91
  %7 = call i64 @func3(), !insn.addr !92
  %8 = call i64 @func4(), !insn.addr !93
  ret i64 0, !insn.addr !94

; uselistorder directives
  uselistorder i64 ()* @f_scanf_nop, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
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
!11 = !{i64 272}
!12 = !{i64 280}
!13 = !{i64 368}
!14 = !{i64 376}
!15 = !{i64 384}
!16 = !{i64 392}
!17 = !{i64 400}
!18 = !{i64 412}
!19 = !{i64 452}
!20 = !{i64 460}
!21 = !{i64 468}
!22 = !{i64 476}
!23 = !{i64 484}
!24 = !{i64 584}
!25 = !{i64 608}
!26 = !{i64 636}
!27 = !{i64 644}
!28 = !{i64 656}
!29 = !{i64 692}
!30 = !{i64 700}
!31 = !{i64 708}
!32 = !{i64 716}
!33 = !{i64 724}
!34 = !{i64 784}
!35 = !{i64 796}
!36 = !{i64 804}
!37 = !{i64 840}
!38 = !{i64 764}
!39 = !{i64 772}
!40 = !{i64 852}
!41 = !{i64 860}
!42 = !{i64 908}
!43 = !{i64 916}
!44 = !{i64 928}
!45 = !{i64 964}
!46 = !{i64 968}
!47 = !{i64 972}
!48 = !{i64 980}
!49 = !{i64 988}
!50 = !{i64 992}
!51 = !{i64 996}
!52 = !{i64 1000}
!53 = !{i64 1028}
!54 = !{i64 1036}
!55 = !{i64 1048}
!56 = !{i64 1072}
!57 = !{i64 1096}
!58 = !{i64 1140}
!59 = !{i64 1148}
!60 = !{i64 1156}
!61 = !{i64 1172}
!62 = !{i64 1180}
!63 = !{i64 1188}
!64 = !{i64 1196}
!65 = !{i64 1208}
!66 = !{i64 1240}
!67 = !{i64 1252}
!68 = !{i64 1260}
!69 = !{i64 1264}
!70 = !{i64 1268}
!71 = !{i64 1272}
!72 = !{i64 1276}
!73 = !{i64 1280}
!74 = !{i64 1284}
!75 = !{i64 1316}
!76 = !{i64 1328}
!77 = !{i64 1364}
!78 = !{i64 1372}
!79 = !{i64 1456}
!80 = !{i64 1388}
!81 = !{i64 1396}
!82 = !{i64 1468}
!83 = !{i64 1476}
!84 = !{i64 1488}
!85 = !{i64 1516}
!86 = !{i64 1524}
!87 = !{i64 1532}
!88 = !{i64 1540}
!89 = !{i64 1556}
!90 = !{i64 1572}
!91 = !{i64 1584}
!92 = !{i64 1596}
!93 = !{i64 1616}
!94 = !{i64 1636}
