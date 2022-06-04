source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

define i64 @function_0() local_unnamed_addr {
dec_label_pc_0:
  br label %dec_label_pc_10, !insn.addr !0

dec_label_pc_10:                                  ; preds = %dec_label_pc_10, %dec_label_pc_0
  br label %dec_label_pc_10, !insn.addr !1
}

define i64 @function_14() local_unnamed_addr {
dec_label_pc_14:
  %0 = alloca i32
  %1 = load i32, i32* %0
  %2 = zext i32 %1 to i64, !insn.addr !2
  ret i64 %2, !insn.addr !3
}

define i64 @function_40(i64 %arg1) local_unnamed_addr {
dec_label_pc_40:
  %0 = call i64 @function_40(i64 %arg1), !insn.addr !4
  ret i64 %0, !insn.addr !4
}

define i64 @function_44() local_unnamed_addr {
dec_label_pc_44:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = call i64 @function_14(), !insn.addr !5
  %4 = call i64 @function_14(), !insn.addr !6
  %5 = call i64 @function_40(i64 %4), !insn.addr !7
  %6 = call i64 @function_14(), !insn.addr !8
  %7 = call i64 @function_40(i64 %6), !insn.addr !9
  %8 = mul i64 %2, 2, !insn.addr !10
  %9 = sub i64 %8, %1, !insn.addr !11
  %10 = sub i64 %9, %5, !insn.addr !12
  %11 = add i64 %7, %6, !insn.addr !13
  %12 = mul i64 %10, 700, !insn.addr !14
  %13 = add i64 %11, %12, !insn.addr !14
  %14 = mul i64 %13, %7, !insn.addr !15
  %15 = add i64 %14, %6, !insn.addr !15
  %16 = and i64 %15, 4294967295, !insn.addr !15
  ret i64 %16, !insn.addr !16

; uselistorder directives
  uselistorder i64* %0, { 1, 0 }
}

define i64 @function_a4() local_unnamed_addr {
dec_label_pc_a4:
  %0 = call i64 @function_14(), !insn.addr !17
  %1 = call i64 @function_40(i64 %0), !insn.addr !18
  %2 = call i64 @function_14(), !insn.addr !19
  %3 = call i64 @function_14(), !insn.addr !20
  %4 = call i64 @function_14(), !insn.addr !21
  %5 = call i64 @function_0(), !insn.addr !22
  %6 = call i64 @function_0(), !insn.addr !23
  %7 = add i64 %0, 233, !insn.addr !24
  %8 = and i64 %7, 4294967295, !insn.addr !24
  ret i64 %8, !insn.addr !25
}

define i64 @function_104() local_unnamed_addr {
dec_label_pc_104:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_40(i64 %1), !insn.addr !26
  %3 = call i64 @function_40(i64 %2), !insn.addr !27
  %4 = call i64 @function_14(), !insn.addr !28
  %5 = call i64 @function_14(), !insn.addr !29
  %6 = call i64 @function_40(i64 %5), !insn.addr !30
  %7 = call i64 @function_0(), !insn.addr !31
  %8 = add i64 %3, 4294966677, !insn.addr !32
  %9 = mul i64 %5, %8, !insn.addr !33
  %10 = call i64 @function_0(), !insn.addr !34
  %11 = mul i64 %2, -4294966677, !insn.addr !35
  %.neg1 = mul i64 %11, %4
  %.neg2 = sub i64 %4, %3, !insn.addr !35
  %12 = add i64 %.neg2, %.neg1, !insn.addr !36
  %13 = mul i64 %12, %3, !insn.addr !37
  %14 = add i64 %13, %9, !insn.addr !37
  %15 = and i64 %14, 4294967295, !insn.addr !37
  ret i64 %15, !insn.addr !38

; uselistorder directives
  uselistorder i64 %3, { 1, 0, 2 }
}

define i64 @function_178() local_unnamed_addr {
dec_label_pc_178:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_40(i64 %1), !insn.addr !39
  %3 = call i64 @function_14(), !insn.addr !40
  %4 = call i64 @function_40(i64 %3), !insn.addr !41
  %5 = call i64 @function_40(i64 %4), !insn.addr !42
  %6 = call i64 @function_40(i64 %5), !insn.addr !43
  %7 = mul i64 %2, 737, !insn.addr !44
  %8 = add i64 %5, %7, !insn.addr !44
  %9 = call i64 @function_0(), !insn.addr !45
  %10 = call i64 @function_0(), !insn.addr !46
  %11 = call i64 @function_0(), !insn.addr !47
  %12 = sub i64 %8, %6, !insn.addr !48
  %13 = mul i64 %8, %2, !insn.addr !49
  %14 = add i64 %12, %13, !insn.addr !49
  %15 = mul i64 %6, 4294967202, !insn.addr !50
  %16 = mul i64 %15, %14, !insn.addr !51
  %17 = add i64 %16, %6, !insn.addr !51
  %18 = and i64 %17, 4294967295, !insn.addr !51
  ret i64 %18, !insn.addr !52

; uselistorder directives
  uselistorder i64 %8, { 1, 0 }
  uselistorder i64 %6, { 1, 2, 0 }
}

define i64 @function_1fc() local_unnamed_addr {
dec_label_pc_1fc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = call i64 @function_40(i64 %2), !insn.addr !53
  %4 = call i64 @function_40(i64 %3), !insn.addr !54
  %5 = call i64 @function_14(), !insn.addr !55
  %6 = call i64 @function_14(), !insn.addr !56
  %7 = call i64 @function_40(i64 %6), !insn.addr !57
  %8 = sub i64 %4, %1, !insn.addr !58
  %9 = call i64 @function_0(), !insn.addr !59
  %10 = add i64 %8, 4294966447, !insn.addr !60
  %11 = call i64 @function_0(), !insn.addr !61
  %12 = add i64 %5, %1
  %13 = sub i64 %8, %12, !insn.addr !62
  %14 = add i64 %13, %6, !insn.addr !63
  %15 = mul i64 %10, %6, !insn.addr !64
  %16 = add i64 %14, %15, !insn.addr !64
  %17 = and i64 %16, 4294967295, !insn.addr !64
  ret i64 %17, !insn.addr !65

; uselistorder directives
  uselistorder i64 %6, { 1, 0, 2 }
  uselistorder i64 %1, { 1, 0 }
  uselistorder i64* %0, { 1, 0 }
  uselistorder i64 ()* @function_0, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 (i64)* @function_40, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i32 1, { 3, 2, 1, 0, 4 }
}

define i64 @function_27c() local_unnamed_addr {
dec_label_pc_27c:
  %0 = call i64 @function_14(), !insn.addr !66
  %1 = call i64 @function_14(), !insn.addr !67
  %2 = call i64 @function_14(), !insn.addr !68
  %3 = call i64 @function_14(), !insn.addr !69
  %4 = call i64 @function_44(), !insn.addr !70
  %5 = call i64 @function_a4(), !insn.addr !71
  %6 = call i64 @function_104(), !insn.addr !72
  %7 = call i64 @function_178(), !insn.addr !73
  %8 = call i64 @function_1fc(), !insn.addr !74
  ret i64 0, !insn.addr !75

; uselistorder directives
  uselistorder i64 ()* @function_14, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 12}
!1 = !{i64 16}
!2 = !{i64 48}
!3 = !{i64 60}
!4 = !{i64 64}
!5 = !{i64 92}
!6 = !{i64 96}
!7 = !{i64 100}
!8 = !{i64 108}
!9 = !{i64 116}
!10 = !{i64 120}
!11 = !{i64 124}
!12 = !{i64 140}
!13 = !{i64 144}
!14 = !{i64 148}
!15 = !{i64 152}
!16 = !{i64 160}
!17 = !{i64 184}
!18 = !{i64 192}
!19 = !{i64 196}
!20 = !{i64 200}
!21 = !{i64 208}
!22 = !{i64 224}
!23 = !{i64 236}
!24 = !{i64 240}
!25 = !{i64 256}
!26 = !{i64 276}
!27 = !{i64 284}
!28 = !{i64 292}
!29 = !{i64 300}
!30 = !{i64 308}
!31 = !{i64 328}
!32 = !{i64 336}
!33 = !{i64 344}
!34 = !{i64 348}
!35 = !{i64 320}
!36 = !{i64 352}
!37 = !{i64 356}
!38 = !{i64 372}
!39 = !{i64 396}
!40 = !{i64 404}
!41 = !{i64 412}
!42 = !{i64 420}
!43 = !{i64 428}
!44 = !{i64 436}
!45 = !{i64 448}
!46 = !{i64 456}
!47 = !{i64 464}
!48 = !{i64 468}
!49 = !{i64 472}
!50 = !{i64 488}
!51 = !{i64 496}
!52 = !{i64 504}
!53 = !{i64 536}
!54 = !{i64 540}
!55 = !{i64 548}
!56 = !{i64 556}
!57 = !{i64 564}
!58 = !{i64 568}
!59 = !{i64 576}
!60 = !{i64 592}
!61 = !{i64 596}
!62 = !{i64 604}
!63 = !{i64 620}
!64 = !{i64 624}
!65 = !{i64 632}
!66 = !{i64 652}
!67 = !{i64 660}
!68 = !{i64 668}
!69 = !{i64 676}
!70 = !{i64 688}
!71 = !{i64 696}
!72 = !{i64 700}
!73 = !{i64 708}
!74 = !{i64 720}
!75 = !{i64 740}
