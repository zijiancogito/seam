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
  %0 = call i64 @function_30(), !insn.addr !7
  %1 = call i64 @function_30(), !insn.addr !8
  %2 = call i64 @function_30(), !insn.addr !9
  %3 = call i64 @function_30(), !insn.addr !10
  %4 = call i64 @function_30(), !insn.addr !11
  %5 = mul i64 %3, %1, !insn.addr !12
  %6 = call i64 @function_0(), !insn.addr !13
  %7 = sub i64 %5, %3, !insn.addr !14
  %8 = and i64 %7, 4294967295, !insn.addr !15
  ret i64 %8, !insn.addr !16

; uselistorder directives
  uselistorder i64 %3, { 1, 0 }
}

define i64 @function_160() local_unnamed_addr {
dec_label_pc_160:
  %0 = call i64 @function_60(), !insn.addr !17
  %1 = call i64 @function_60(), !insn.addr !18
  %2 = call i64 @function_30(), !insn.addr !19
  %3 = call i64 @function_30(), !insn.addr !20
  %4 = call i64 @function_60(), !insn.addr !21
  %5 = call i64 @function_0(), !insn.addr !22
  %6 = call i64 @function_0(), !insn.addr !23
  %7 = add i64 %3, %1, !insn.addr !24
  %8 = mul i64 %7, %4, !insn.addr !25
  %9 = call i64 @function_0(), !insn.addr !26
  %10 = add i64 %1, 4294967284, !insn.addr !27
  %11 = add i64 %10, %2, !insn.addr !28
  %12 = sub i64 %11, %4, !insn.addr !29
  %13 = add i64 %12, %8, !insn.addr !30
  %14 = and i64 %13, 4294967295, !insn.addr !31
  ret i64 %14, !insn.addr !32

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @function_27c() local_unnamed_addr {
dec_label_pc_27c:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_30(), !insn.addr !33
  %3 = call i64 @function_30(), !insn.addr !34
  %4 = call i64 @function_60(), !insn.addr !35
  %5 = call i64 @function_60(), !insn.addr !36
  %6 = call i64 @function_60(), !insn.addr !37
  %7 = call i64 @function_0(), !insn.addr !38
  %8 = call i64 @function_0(), !insn.addr !39
  %9 = call i64 @function_0(), !insn.addr !40
  %10 = sub i64 770, %1, !insn.addr !41
  %11 = and i64 %10, 4294967295, !insn.addr !42
  ret i64 %11, !insn.addr !43

; uselistorder directives
  uselistorder i32 1, { 2, 1, 0, 3 }
}

define i64 @function_368() local_unnamed_addr {
dec_label_pc_368:
  %0 = call i64 @function_60(), !insn.addr !44
  %1 = call i64 @function_60(), !insn.addr !45
  %2 = call i64 @function_60(), !insn.addr !46
  %3 = call i64 @function_60(), !insn.addr !47
  %4 = call i64 @function_30(), !insn.addr !48
  %5 = call i64 @function_0(), !insn.addr !49
  %6 = call i64 @function_0(), !insn.addr !50
  %7 = call i64 @function_0(), !insn.addr !51
  %8 = call i64 @function_0(), !insn.addr !52
  %9 = call i64 @function_0(), !insn.addr !53
  %10 = sub i64 %2, %3, !insn.addr !54
  %11 = and i64 %10, 4294967295, !insn.addr !55
  ret i64 %11, !insn.addr !56
}

define i64 @function_490() local_unnamed_addr {
dec_label_pc_490:
  %0 = call i64 @function_60(), !insn.addr !57
  %1 = call i64 @function_60(), !insn.addr !58
  %2 = call i64 @function_30(), !insn.addr !59
  %3 = call i64 @function_30(), !insn.addr !60
  %4 = call i64 @function_30(), !insn.addr !61
  %5 = call i64 @function_0(), !insn.addr !62
  %6 = call i64 @function_0(), !insn.addr !63
  %7 = sub i64 4294966620, %0, !insn.addr !64
  %8 = add i64 %7, %1, !insn.addr !65
  %9 = sub i64 %8, %2, !insn.addr !66
  %10 = add i64 %9, %4, !insn.addr !67
  %11 = and i64 %10, 4294967295, !insn.addr !68
  ret i64 %11, !insn.addr !69

; uselistorder directives
  uselistorder i64 4294967295, { 1, 2, 3, 4, 5, 0 }
  uselistorder i64 ()* @function_0, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @function_58c() local_unnamed_addr {
dec_label_pc_58c:
  %0 = call i64 @function_30(), !insn.addr !70
  %1 = call i64 @function_30(), !insn.addr !71
  %2 = call i64 @function_60(), !insn.addr !72
  %3 = call i64 @function_30(), !insn.addr !73
  %4 = call i64 @function_8c(), !insn.addr !74
  %5 = call i64 @function_160(), !insn.addr !75
  %6 = call i64 @function_27c(), !insn.addr !76
  %7 = call i64 @function_368(), !insn.addr !77
  %8 = call i64 @function_490(), !insn.addr !78
  ret i64 0, !insn.addr !79

; uselistorder directives
  uselistorder i64 ()* @function_60, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @function_30, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 44}
!1 = !{i64 80}
!2 = !{i64 92}
!3 = !{i64 116}
!4 = !{i64 120}
!5 = !{i64 124}
!6 = !{i64 136}
!7 = !{i64 168}
!8 = !{i64 176}
!9 = !{i64 184}
!10 = !{i64 192}
!11 = !{i64 200}
!12 = !{i64 232}
!13 = !{i64 316}
!14 = !{i64 328}
!15 = !{i64 336}
!16 = !{i64 348}
!17 = !{i64 388}
!18 = !{i64 396}
!19 = !{i64 404}
!20 = !{i64 412}
!21 = !{i64 420}
!22 = !{i64 496}
!23 = !{i64 528}
!24 = !{i64 540}
!25 = !{i64 548}
!26 = !{i64 576}
!27 = !{i64 564}
!28 = !{i64 588}
!29 = !{i64 596}
!30 = !{i64 612}
!31 = !{i64 620}
!32 = !{i64 632}
!33 = !{i64 672}
!34 = !{i64 680}
!35 = !{i64 688}
!36 = !{i64 696}
!37 = !{i64 704}
!38 = !{i64 748}
!39 = !{i64 780}
!40 = !{i64 804}
!41 = !{i64 848}
!42 = !{i64 856}
!43 = !{i64 868}
!44 = !{i64 912}
!45 = !{i64 920}
!46 = !{i64 928}
!47 = !{i64 936}
!48 = !{i64 944}
!49 = !{i64 988}
!50 = !{i64 1012}
!51 = !{i64 1052}
!52 = !{i64 1108}
!53 = !{i64 1132}
!54 = !{i64 1144}
!55 = !{i64 1152}
!56 = !{i64 1164}
!57 = !{i64 1196}
!58 = !{i64 1204}
!59 = !{i64 1212}
!60 = !{i64 1220}
!61 = !{i64 1228}
!62 = !{i64 1328}
!63 = !{i64 1352}
!64 = !{i64 1260}
!65 = !{i64 1268}
!66 = !{i64 1276}
!67 = !{i64 1396}
!68 = !{i64 1404}
!69 = !{i64 1416}
!70 = !{i64 1444}
!71 = !{i64 1452}
!72 = !{i64 1460}
!73 = !{i64 1468}
!74 = !{i64 1476}
!75 = !{i64 1492}
!76 = !{i64 1508}
!77 = !{i64 1528}
!78 = !{i64 1532}
!79 = !{i64 1552}
