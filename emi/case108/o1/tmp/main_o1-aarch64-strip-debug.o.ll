source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@0 = external global i32

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
  %8 = add i64 %2, %1, !insn.addr !8
  %9 = add i64 %8, %6, !insn.addr !9
  %10 = sub i64 %1, %3, !insn.addr !10
  %11 = mul i64 %9, %3, !insn.addr !11
  %12 = add i64 %10, %11, !insn.addr !11
  %13 = call i64 @f_printf(), !insn.addr !12
  %14 = call i64 @f_printf(), !insn.addr !13
  %15 = mul i64 %12, %4, !insn.addr !14
  %16 = and i64 %15, 4294967295, !insn.addr !14
  ret i64 %16, !insn.addr !15

; uselistorder directives
  uselistorder i64 %3, { 1, 0, 2 }
  uselistorder i64 %1, { 2, 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_bc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @f_scanf_nop(), !insn.addr !16
  %3 = call i64 @f_scanf_nop(), !insn.addr !17
  %4 = call i64 @rand(i64 %3), !insn.addr !18
  %5 = call i64 @rand(i64 %4), !insn.addr !19
  %6 = call i64 @rand(i64 %5), !insn.addr !20
  %7 = mul i64 %4, %2, !insn.addr !21
  %8 = add i64 %7, %3, !insn.addr !22
  %9 = call i64 @f_printf(), !insn.addr !23
  %10 = add i64 %4, %3, !insn.addr !24
  %11 = add i64 %10, %6, !insn.addr !25
  %12 = call i64 @f_printf(), !insn.addr !26
  %13 = add i64 %2, %1, !insn.addr !27
  %14 = add i64 %13, %8, !insn.addr !28
  %15 = mul i64 %14, %1, !insn.addr !29
  %16 = mul i64 %8, %2, !insn.addr !30
  %17 = call i64 @f_printf(), !insn.addr !31
  %18 = sub i64 %7, %16
  %19 = sub i64 %15, %8, !insn.addr !32
  %20 = mul i64 %6, %7, !insn.addr !33
  %21 = mul i64 %20, %11, !insn.addr !34
  %22 = mul i64 %21, %18, !insn.addr !35
  %23 = add i64 %19, %22, !insn.addr !35
  %24 = and i64 %23, 4294967295, !insn.addr !35
  ret i64 %24, !insn.addr !36

; uselistorder directives
  uselistorder i64 %7, { 0, 2, 1 }
  uselistorder i64 %1, { 1, 0 }
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_164:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = call i64 @f_scanf_nop(), !insn.addr !37
  %4 = call i64 @rand(i64 %3), !insn.addr !38
  %5 = call i64 @rand(i64 %4), !insn.addr !39
  %6 = call i64 @rand(i64 %5), !insn.addr !40
  %7 = call i64 @rand(i64 %6), !insn.addr !41
  %8 = add i64 %5, 508, !insn.addr !42
  %9 = call i64 @f_printf(), !insn.addr !43
  %10 = sub i64 %2, %5, !insn.addr !44
  %11 = add i64 %1, 583, !insn.addr !45
  %12 = sub i64 %10, %6, !insn.addr !46
  %13 = mul i64 %11, %2, !insn.addr !47
  %14 = mul i64 %13, %8, !insn.addr !48
  %15 = add i64 %14, %8, !insn.addr !49
  %16 = mul i64 %15, %14, !insn.addr !50
  %17 = add i64 %12, %16, !insn.addr !50
  %18 = and i64 %17, 4294967295, !insn.addr !50
  ret i64 %18, !insn.addr !51

; uselistorder directives
  uselistorder i64* %0, { 1, 0 }
  uselistorder i32 1, { 2, 1, 0 }
}

define i64 @func3(i64 %arg1) local_unnamed_addr {
dec_label_pc_1d8:
  %0 = call i64 @f_scanf_nop(), !insn.addr !52
  %1 = call i64 @rand(i64 %0), !insn.addr !53
  %2 = call i64 @f_scanf_nop(), !insn.addr !54
  %3 = call i64 @rand(i64 %2), !insn.addr !55
  %4 = call i64 @rand(i64 %3), !insn.addr !56
  %5 = sub i64 498, %4, !insn.addr !57
  %6 = and i64 %5, 4294967295, !insn.addr !57
  ret i64 %6, !insn.addr !58
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_204:
  %0 = call i64 @f_scanf_nop(), !insn.addr !59
  %1 = call i64 @f_scanf_nop(), !insn.addr !60
  %2 = call i64 @f_scanf_nop(), !insn.addr !61
  %3 = call i64 @f_scanf_nop(), !insn.addr !62
  %4 = call i64 @rand(i64 %3), !insn.addr !63
  %5 = call i64 @f_printf(), !insn.addr !64
  %6 = call i64 @f_printf(), !insn.addr !65
  %7 = mul i64 %1, 4294959443, !insn.addr !66
  %8 = and i64 %7, 4294967295, !insn.addr !66
  ret i64 %8, !insn.addr !67

; uselistorder directives
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_258:
  %0 = call i64 @f_scanf_nop(), !insn.addr !68
  %1 = call i64 @rand(i64 %0), !insn.addr !69
  %2 = call i64 @f_scanf_nop(), !insn.addr !70
  %3 = call i64 @rand(i64 %2), !insn.addr !71
  %4 = call i64 @func0(), !insn.addr !72
  %5 = call i64 @func1(), !insn.addr !73
  %6 = call i64 @func2(), !insn.addr !74
  %7 = call i64 @func3(i64 ptrtoint (i32* @0 to i64)), !insn.addr !75
  %8 = call i64 @func4(), !insn.addr !76
  ret i64 0, !insn.addr !77

; uselistorder directives
  uselistorder i64 (i64)* @rand, { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @f_scanf_nop, { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 12}
!1 = !{i64 40}
!2 = !{i64 92}
!3 = !{i64 100}
!4 = !{i64 108}
!5 = !{i64 116}
!6 = !{i64 120}
!7 = !{i64 132}
!8 = !{i64 136}
!9 = !{i64 140}
!10 = !{i64 144}
!11 = !{i64 148}
!12 = !{i64 152}
!13 = !{i64 160}
!14 = !{i64 164}
!15 = !{i64 184}
!16 = !{i64 216}
!17 = !{i64 224}
!18 = !{i64 232}
!19 = !{i64 240}
!20 = !{i64 244}
!21 = !{i64 248}
!22 = !{i64 252}
!23 = !{i64 264}
!24 = !{i64 268}
!25 = !{i64 272}
!26 = !{i64 280}
!27 = !{i64 284}
!28 = !{i64 288}
!29 = !{i64 296}
!30 = !{i64 300}
!31 = !{i64 312}
!32 = !{i64 324}
!33 = !{i64 292}
!34 = !{i64 320}
!35 = !{i64 344}
!36 = !{i64 352}
!37 = !{i64 384}
!38 = !{i64 388}
!39 = !{i64 392}
!40 = !{i64 400}
!41 = !{i64 408}
!42 = !{i64 412}
!43 = !{i64 420}
!44 = !{i64 424}
!45 = !{i64 428}
!46 = !{i64 432}
!47 = !{i64 436}
!48 = !{i64 452}
!49 = !{i64 456}
!50 = !{i64 460}
!51 = !{i64 468}
!52 = !{i64 480}
!53 = !{i64 484}
!54 = !{i64 488}
!55 = !{i64 492}
!56 = !{i64 496}
!57 = !{i64 504}
!58 = !{i64 512}
!59 = !{i64 528}
!60 = !{i64 536}
!61 = !{i64 544}
!62 = !{i64 548}
!63 = !{i64 552}
!64 = !{i64 568}
!65 = !{i64 576}
!66 = !{i64 588}
!67 = !{i64 596}
!68 = !{i64 612}
!69 = !{i64 620}
!70 = !{i64 628}
!71 = !{i64 632}
!72 = !{i64 640}
!73 = !{i64 648}
!74 = !{i64 660}
!75 = !{i64 664}
!76 = !{i64 668}
!77 = !{i64 684}
