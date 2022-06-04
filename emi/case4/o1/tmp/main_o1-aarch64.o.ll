source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@global_var_2e8 = constant [3 x i8] c"%d\00"

define i64 @f_printf() local_unnamed_addr {
dec_label_pc_0:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = add i64 %1, ptrtoint ([3 x i8]* @global_var_2e8 to i64), !insn.addr !0
  ret i64 %2, !insn.addr !1
}

define i64 @f_scanf_nop() local_unnamed_addr {
dec_label_pc_14:
  ret i64 ptrtoint ([3 x i8]* @global_var_2e8 to i64), !insn.addr !2
}

declare i64 @rand(i64) local_unnamed_addr

define i64 @func0() local_unnamed_addr {
dec_label_pc_44:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = call i64 @f_scanf_nop(), !insn.addr !3
  %4 = call i64 @f_scanf_nop(), !insn.addr !4
  %5 = call i64 @rand(i64 %4), !insn.addr !5
  %6 = call i64 @f_scanf_nop(), !insn.addr !6
  %7 = call i64 @rand(i64 %6), !insn.addr !7
  %8 = mul i64 %2, 2, !insn.addr !8
  %9 = sub i64 %8, %1, !insn.addr !9
  %10 = sub i64 %9, %5, !insn.addr !10
  %11 = add i64 %7, %6, !insn.addr !11
  %12 = mul i64 %10, 700, !insn.addr !12
  %13 = add i64 %11, %12, !insn.addr !12
  %14 = mul i64 %13, %7, !insn.addr !13
  %15 = add i64 %14, %6, !insn.addr !13
  %16 = and i64 %15, 4294967295, !insn.addr !13
  ret i64 %16, !insn.addr !14

; uselistorder directives
  uselistorder i64* %0, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_a4:
  %0 = call i64 @f_scanf_nop(), !insn.addr !15
  %1 = call i64 @rand(i64 %0), !insn.addr !16
  %2 = call i64 @f_scanf_nop(), !insn.addr !17
  %3 = call i64 @f_scanf_nop(), !insn.addr !18
  %4 = call i64 @f_scanf_nop(), !insn.addr !19
  %5 = call i64 @f_printf(), !insn.addr !20
  %6 = call i64 @f_printf(), !insn.addr !21
  %7 = add i64 %0, 233, !insn.addr !22
  %8 = and i64 %7, 4294967295, !insn.addr !22
  ret i64 %8, !insn.addr !23
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_104:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !24
  %3 = call i64 @rand(i64 %2), !insn.addr !25
  %4 = call i64 @f_scanf_nop(), !insn.addr !26
  %5 = call i64 @f_scanf_nop(), !insn.addr !27
  %6 = call i64 @rand(i64 %5), !insn.addr !28
  %7 = call i64 @f_printf(), !insn.addr !29
  %8 = add i64 %3, 4294966677, !insn.addr !30
  %9 = mul i64 %5, %8, !insn.addr !31
  %10 = call i64 @f_printf(), !insn.addr !32
  %11 = mul i64 %2, -4294966677, !insn.addr !33
  %.neg1 = mul i64 %11, %4
  %.neg2 = sub i64 %4, %3, !insn.addr !33
  %12 = add i64 %.neg2, %.neg1, !insn.addr !34
  %13 = mul i64 %12, %3, !insn.addr !35
  %14 = add i64 %13, %9, !insn.addr !35
  %15 = and i64 %14, 4294967295, !insn.addr !35
  ret i64 %15, !insn.addr !36

; uselistorder directives
  uselistorder i64 %3, { 1, 0, 2 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_178:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !37
  %3 = call i64 @f_scanf_nop(), !insn.addr !38
  %4 = call i64 @rand(i64 %3), !insn.addr !39
  %5 = call i64 @rand(i64 %4), !insn.addr !40
  %6 = call i64 @rand(i64 %5), !insn.addr !41
  %7 = mul i64 %2, 737, !insn.addr !42
  %8 = add i64 %5, %7, !insn.addr !42
  %9 = call i64 @f_printf(), !insn.addr !43
  %10 = call i64 @f_printf(), !insn.addr !44
  %11 = call i64 @f_printf(), !insn.addr !45
  %12 = sub i64 %8, %6, !insn.addr !46
  %13 = mul i64 %8, %2, !insn.addr !47
  %14 = add i64 %12, %13, !insn.addr !47
  %15 = mul i64 %6, 4294967202, !insn.addr !48
  %16 = mul i64 %15, %14, !insn.addr !49
  %17 = add i64 %16, %6, !insn.addr !49
  %18 = and i64 %17, 4294967295, !insn.addr !49
  ret i64 %18, !insn.addr !50

; uselistorder directives
  uselistorder i64 %8, { 1, 0 }
  uselistorder i64 %6, { 1, 2, 0 }
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_1fc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = call i64 @rand(i64 %2), !insn.addr !51
  %4 = call i64 @rand(i64 %3), !insn.addr !52
  %5 = call i64 @f_scanf_nop(), !insn.addr !53
  %6 = call i64 @f_scanf_nop(), !insn.addr !54
  %7 = call i64 @rand(i64 %6), !insn.addr !55
  %8 = sub i64 %4, %1, !insn.addr !56
  %9 = call i64 @f_printf(), !insn.addr !57
  %10 = add i64 %8, 4294966447, !insn.addr !58
  %11 = call i64 @f_printf(), !insn.addr !59
  %12 = add i64 %5, %1
  %13 = sub i64 %8, %12, !insn.addr !60
  %14 = add i64 %13, %6, !insn.addr !61
  %15 = mul i64 %10, %6, !insn.addr !62
  %16 = add i64 %14, %15, !insn.addr !62
  %17 = and i64 %16, 4294967295, !insn.addr !62
  ret i64 %17, !insn.addr !63

; uselistorder directives
  uselistorder i64 %6, { 1, 0, 2 }
  uselistorder i64 %1, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 (i64)* @rand, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_27c:
  %0 = call i64 @f_scanf_nop(), !insn.addr !64
  %1 = call i64 @f_scanf_nop(), !insn.addr !65
  %2 = call i64 @f_scanf_nop(), !insn.addr !66
  %3 = call i64 @f_scanf_nop(), !insn.addr !67
  %4 = call i64 @func0(), !insn.addr !68
  %5 = call i64 @func1(), !insn.addr !69
  %6 = call i64 @func2(), !insn.addr !70
  %7 = call i64 @func3(), !insn.addr !71
  %8 = call i64 @func4(), !insn.addr !72
  ret i64 0, !insn.addr !73

; uselistorder directives
  uselistorder i64 ()* @f_scanf_nop, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @"$d.1"() local_unnamed_addr {
dec_label_pc_2e8:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1

; uselistorder directives
  uselistorder i32 1, { 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 4}
!1 = !{i64 12}
!2 = !{i64 40}
!3 = !{i64 92}
!4 = !{i64 96}
!5 = !{i64 100}
!6 = !{i64 108}
!7 = !{i64 116}
!8 = !{i64 120}
!9 = !{i64 124}
!10 = !{i64 140}
!11 = !{i64 144}
!12 = !{i64 148}
!13 = !{i64 152}
!14 = !{i64 160}
!15 = !{i64 184}
!16 = !{i64 192}
!17 = !{i64 196}
!18 = !{i64 200}
!19 = !{i64 208}
!20 = !{i64 224}
!21 = !{i64 236}
!22 = !{i64 240}
!23 = !{i64 256}
!24 = !{i64 276}
!25 = !{i64 284}
!26 = !{i64 292}
!27 = !{i64 300}
!28 = !{i64 308}
!29 = !{i64 328}
!30 = !{i64 336}
!31 = !{i64 344}
!32 = !{i64 348}
!33 = !{i64 320}
!34 = !{i64 352}
!35 = !{i64 356}
!36 = !{i64 372}
!37 = !{i64 396}
!38 = !{i64 404}
!39 = !{i64 412}
!40 = !{i64 420}
!41 = !{i64 428}
!42 = !{i64 436}
!43 = !{i64 448}
!44 = !{i64 456}
!45 = !{i64 464}
!46 = !{i64 468}
!47 = !{i64 472}
!48 = !{i64 488}
!49 = !{i64 496}
!50 = !{i64 504}
!51 = !{i64 536}
!52 = !{i64 540}
!53 = !{i64 548}
!54 = !{i64 556}
!55 = !{i64 564}
!56 = !{i64 568}
!57 = !{i64 576}
!58 = !{i64 592}
!59 = !{i64 596}
!60 = !{i64 604}
!61 = !{i64 620}
!62 = !{i64 624}
!63 = !{i64 632}
!64 = !{i64 652}
!65 = !{i64 660}
!66 = !{i64 668}
!67 = !{i64 676}
!68 = !{i64 688}
!69 = !{i64 696}
!70 = !{i64 700}
!71 = !{i64 708}
!72 = !{i64 720}
!73 = !{i64 740}
