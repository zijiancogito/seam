source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

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
  %2 = load i64, i64* %0
  %3 = call i64 @f_scanf_nop(), !insn.addr !2
  %4 = call i64 @f_scanf_nop(), !insn.addr !3
  %5 = call i64 @rand(i64 %4), !insn.addr !4
  %6 = call i64 @f_scanf_nop(), !insn.addr !5
  %7 = call i64 @rand(i64 %6), !insn.addr !6
  %8 = mul i64 %2, 2, !insn.addr !7
  %9 = sub i64 %8, %1, !insn.addr !8
  %10 = sub i64 %9, %5, !insn.addr !9
  %11 = add i64 %7, %6, !insn.addr !10
  %12 = mul i64 %10, 700, !insn.addr !11
  %13 = add i64 %11, %12, !insn.addr !11
  %14 = mul i64 %13, %7, !insn.addr !12
  %15 = add i64 %14, %6, !insn.addr !12
  %16 = and i64 %15, 4294967295, !insn.addr !12
  ret i64 %16, !insn.addr !13

; uselistorder directives
  uselistorder i64* %0, { 1, 0 }
}

define i64 @func1() local_unnamed_addr {
dec_label_pc_a4:
  %0 = call i64 @f_scanf_nop(), !insn.addr !14
  %1 = call i64 @rand(i64 %0), !insn.addr !15
  %2 = call i64 @f_scanf_nop(), !insn.addr !16
  %3 = call i64 @f_scanf_nop(), !insn.addr !17
  %4 = call i64 @f_scanf_nop(), !insn.addr !18
  %5 = call i64 @f_printf(), !insn.addr !19
  %6 = call i64 @f_printf(), !insn.addr !20
  %7 = add i64 %0, 233, !insn.addr !21
  %8 = and i64 %7, 4294967295, !insn.addr !21
  ret i64 %8, !insn.addr !22
}

define i64 @func2() local_unnamed_addr {
dec_label_pc_104:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !23
  %3 = call i64 @rand(i64 %2), !insn.addr !24
  %4 = call i64 @f_scanf_nop(), !insn.addr !25
  %5 = call i64 @f_scanf_nop(), !insn.addr !26
  %6 = call i64 @rand(i64 %5), !insn.addr !27
  %7 = call i64 @f_printf(), !insn.addr !28
  %8 = add i64 %3, 4294966677, !insn.addr !29
  %9 = mul i64 %5, %8, !insn.addr !30
  %10 = call i64 @f_printf(), !insn.addr !31
  %11 = mul i64 %2, -4294966677, !insn.addr !32
  %.neg1 = mul i64 %11, %4
  %.neg2 = sub i64 %4, %3, !insn.addr !32
  %12 = add i64 %.neg2, %.neg1, !insn.addr !33
  %13 = mul i64 %12, %3, !insn.addr !34
  %14 = add i64 %13, %9, !insn.addr !34
  %15 = and i64 %14, 4294967295, !insn.addr !34
  ret i64 %15, !insn.addr !35

; uselistorder directives
  uselistorder i64 %3, { 1, 0, 2 }
}

define i64 @func3() local_unnamed_addr {
dec_label_pc_178:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @rand(i64 %1), !insn.addr !36
  %3 = call i64 @f_scanf_nop(), !insn.addr !37
  %4 = call i64 @rand(i64 %3), !insn.addr !38
  %5 = call i64 @rand(i64 %4), !insn.addr !39
  %6 = call i64 @rand(i64 %5), !insn.addr !40
  %7 = mul i64 %2, 737, !insn.addr !41
  %8 = add i64 %5, %7, !insn.addr !41
  %9 = call i64 @f_printf(), !insn.addr !42
  %10 = call i64 @f_printf(), !insn.addr !43
  %11 = call i64 @f_printf(), !insn.addr !44
  %12 = sub i64 %8, %6, !insn.addr !45
  %13 = mul i64 %8, %2, !insn.addr !46
  %14 = add i64 %12, %13, !insn.addr !46
  %15 = mul i64 %6, 4294967202, !insn.addr !47
  %16 = mul i64 %15, %14, !insn.addr !48
  %17 = add i64 %16, %6, !insn.addr !48
  %18 = and i64 %17, 4294967295, !insn.addr !48
  ret i64 %18, !insn.addr !49

; uselistorder directives
  uselistorder i64 %8, { 1, 0 }
  uselistorder i64 %6, { 1, 2, 0 }
}

define i64 @func4() local_unnamed_addr {
dec_label_pc_1fc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = call i64 @rand(i64 %2), !insn.addr !50
  %4 = call i64 @rand(i64 %3), !insn.addr !51
  %5 = call i64 @f_scanf_nop(), !insn.addr !52
  %6 = call i64 @f_scanf_nop(), !insn.addr !53
  %7 = call i64 @rand(i64 %6), !insn.addr !54
  %8 = sub i64 %4, %1, !insn.addr !55
  %9 = call i64 @f_printf(), !insn.addr !56
  %10 = add i64 %8, 4294966447, !insn.addr !57
  %11 = call i64 @f_printf(), !insn.addr !58
  %12 = add i64 %5, %1
  %13 = sub i64 %8, %12, !insn.addr !59
  %14 = add i64 %13, %6, !insn.addr !60
  %15 = mul i64 %10, %6, !insn.addr !61
  %16 = add i64 %14, %15, !insn.addr !61
  %17 = and i64 %16, 4294967295, !insn.addr !61
  ret i64 %17, !insn.addr !62

; uselistorder directives
  uselistorder i64 %6, { 1, 0, 2 }
  uselistorder i64 %1, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
  uselistorder i64 ()* @f_printf, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 (i64)* @rand, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i32 1, { 3, 2, 1, 0 }
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_27c:
  %0 = call i64 @f_scanf_nop(), !insn.addr !63
  %1 = call i64 @f_scanf_nop(), !insn.addr !64
  %2 = call i64 @f_scanf_nop(), !insn.addr !65
  %3 = call i64 @f_scanf_nop(), !insn.addr !66
  %4 = call i64 @func0(), !insn.addr !67
  %5 = call i64 @func1(), !insn.addr !68
  %6 = call i64 @func2(), !insn.addr !69
  %7 = call i64 @func3(), !insn.addr !70
  %8 = call i64 @func4(), !insn.addr !71
  ret i64 0, !insn.addr !72

; uselistorder directives
  uselistorder i64 ()* @f_scanf_nop, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 12}
!1 = !{i64 40}
!2 = !{i64 92}
!3 = !{i64 96}
!4 = !{i64 100}
!5 = !{i64 108}
!6 = !{i64 116}
!7 = !{i64 120}
!8 = !{i64 124}
!9 = !{i64 140}
!10 = !{i64 144}
!11 = !{i64 148}
!12 = !{i64 152}
!13 = !{i64 160}
!14 = !{i64 184}
!15 = !{i64 192}
!16 = !{i64 196}
!17 = !{i64 200}
!18 = !{i64 208}
!19 = !{i64 224}
!20 = !{i64 236}
!21 = !{i64 240}
!22 = !{i64 256}
!23 = !{i64 276}
!24 = !{i64 284}
!25 = !{i64 292}
!26 = !{i64 300}
!27 = !{i64 308}
!28 = !{i64 328}
!29 = !{i64 336}
!30 = !{i64 344}
!31 = !{i64 348}
!32 = !{i64 320}
!33 = !{i64 352}
!34 = !{i64 356}
!35 = !{i64 372}
!36 = !{i64 396}
!37 = !{i64 404}
!38 = !{i64 412}
!39 = !{i64 420}
!40 = !{i64 428}
!41 = !{i64 436}
!42 = !{i64 448}
!43 = !{i64 456}
!44 = !{i64 464}
!45 = !{i64 468}
!46 = !{i64 472}
!47 = !{i64 488}
!48 = !{i64 496}
!49 = !{i64 504}
!50 = !{i64 536}
!51 = !{i64 540}
!52 = !{i64 548}
!53 = !{i64 556}
!54 = !{i64 564}
!55 = !{i64 568}
!56 = !{i64 576}
!57 = !{i64 592}
!58 = !{i64 596}
!59 = !{i64 604}
!60 = !{i64 620}
!61 = !{i64 624}
!62 = !{i64 632}
!63 = !{i64 652}
!64 = !{i64 660}
!65 = !{i64 668}
!66 = !{i64 676}
!67 = !{i64 688}
!68 = !{i64 696}
!69 = !{i64 700}
!70 = !{i64 708}
!71 = !{i64 720}
!72 = !{i64 740}
