source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@0 = external global i32

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
  %2 = call i64 @function_40(i64 %1), !insn.addr !5
  %3 = call i64 @function_14(), !insn.addr !6
  %4 = call i64 @function_40(i64 %3), !insn.addr !7
  %5 = call i64 @function_40(i64 %4), !insn.addr !8
  %6 = call i64 @function_40(i64 %5), !insn.addr !9
  %7 = call i64 @function_0(), !insn.addr !10
  %8 = add i64 %2, %1, !insn.addr !11
  %9 = add i64 %8, %6, !insn.addr !12
  %10 = sub i64 %1, %3, !insn.addr !13
  %11 = mul i64 %9, %3, !insn.addr !14
  %12 = add i64 %10, %11, !insn.addr !14
  %13 = call i64 @function_0(), !insn.addr !15
  %14 = call i64 @function_0(), !insn.addr !16
  %15 = mul i64 %12, %4, !insn.addr !17
  %16 = and i64 %15, 4294967295, !insn.addr !17
  ret i64 %16, !insn.addr !18

; uselistorder directives
  uselistorder i64 %3, { 1, 0, 2 }
  uselistorder i64 %1, { 2, 1, 0 }
}

define i64 @function_bc() local_unnamed_addr {
dec_label_pc_bc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_14(), !insn.addr !19
  %3 = call i64 @function_14(), !insn.addr !20
  %4 = call i64 @function_40(i64 %3), !insn.addr !21
  %5 = call i64 @function_40(i64 %4), !insn.addr !22
  %6 = call i64 @function_40(i64 %5), !insn.addr !23
  %7 = mul i64 %4, %2, !insn.addr !24
  %8 = add i64 %7, %3, !insn.addr !25
  %9 = call i64 @function_0(), !insn.addr !26
  %10 = add i64 %4, %3, !insn.addr !27
  %11 = add i64 %10, %6, !insn.addr !28
  %12 = call i64 @function_0(), !insn.addr !29
  %13 = add i64 %2, %1, !insn.addr !30
  %14 = add i64 %13, %8, !insn.addr !31
  %15 = mul i64 %14, %1, !insn.addr !32
  %16 = mul i64 %8, %2, !insn.addr !33
  %17 = call i64 @function_0(), !insn.addr !34
  %18 = sub i64 %7, %16
  %19 = sub i64 %15, %8, !insn.addr !35
  %20 = mul i64 %6, %7, !insn.addr !36
  %21 = mul i64 %20, %11, !insn.addr !37
  %22 = mul i64 %21, %18, !insn.addr !38
  %23 = add i64 %19, %22, !insn.addr !38
  %24 = and i64 %23, 4294967295, !insn.addr !38
  ret i64 %24, !insn.addr !39

; uselistorder directives
  uselistorder i64 %7, { 0, 2, 1 }
  uselistorder i64 %1, { 1, 0 }
}

define i64 @function_164() local_unnamed_addr {
dec_label_pc_164:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i64, i64* %0
  %3 = call i64 @function_14(), !insn.addr !40
  %4 = call i64 @function_40(i64 %3), !insn.addr !41
  %5 = call i64 @function_40(i64 %4), !insn.addr !42
  %6 = call i64 @function_40(i64 %5), !insn.addr !43
  %7 = call i64 @function_40(i64 %6), !insn.addr !44
  %8 = add i64 %5, 508, !insn.addr !45
  %9 = call i64 @function_0(), !insn.addr !46
  %10 = sub i64 %2, %5, !insn.addr !47
  %11 = add i64 %1, 583, !insn.addr !48
  %12 = sub i64 %10, %6, !insn.addr !49
  %13 = mul i64 %11, %2, !insn.addr !50
  %14 = mul i64 %13, %8, !insn.addr !51
  %15 = add i64 %14, %8, !insn.addr !52
  %16 = mul i64 %15, %14, !insn.addr !53
  %17 = add i64 %12, %16, !insn.addr !53
  %18 = and i64 %17, 4294967295, !insn.addr !53
  ret i64 %18, !insn.addr !54

; uselistorder directives
  uselistorder i64* %0, { 1, 0 }
  uselistorder i32 1, { 2, 1, 0, 3 }
}

define i64 @function_1d8(i64 %arg1) local_unnamed_addr {
dec_label_pc_1d8:
  %0 = call i64 @function_14(), !insn.addr !55
  %1 = call i64 @function_40(i64 %0), !insn.addr !56
  %2 = call i64 @function_14(), !insn.addr !57
  %3 = call i64 @function_40(i64 %2), !insn.addr !58
  %4 = call i64 @function_40(i64 %3), !insn.addr !59
  %5 = sub i64 498, %4, !insn.addr !60
  %6 = and i64 %5, 4294967295, !insn.addr !60
  ret i64 %6, !insn.addr !61
}

define i64 @function_204() local_unnamed_addr {
dec_label_pc_204:
  %0 = call i64 @function_14(), !insn.addr !62
  %1 = call i64 @function_14(), !insn.addr !63
  %2 = call i64 @function_14(), !insn.addr !64
  %3 = call i64 @function_14(), !insn.addr !65
  %4 = call i64 @function_40(i64 %3), !insn.addr !66
  %5 = call i64 @function_0(), !insn.addr !67
  %6 = call i64 @function_0(), !insn.addr !68
  %7 = mul i64 %1, 4294959443, !insn.addr !69
  %8 = and i64 %7, 4294967295, !insn.addr !69
  ret i64 %8, !insn.addr !70

; uselistorder directives
  uselistorder i64 ()* @function_0, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @function_258() local_unnamed_addr {
dec_label_pc_258:
  %0 = call i64 @function_14(), !insn.addr !71
  %1 = call i64 @function_40(i64 %0), !insn.addr !72
  %2 = call i64 @function_14(), !insn.addr !73
  %3 = call i64 @function_40(i64 %2), !insn.addr !74
  %4 = call i64 @function_44(), !insn.addr !75
  %5 = call i64 @function_bc(), !insn.addr !76
  %6 = call i64 @function_164(), !insn.addr !77
  %7 = call i64 @function_1d8(i64 ptrtoint (i32* @0 to i64)), !insn.addr !78
  %8 = call i64 @function_204(), !insn.addr !79
  ret i64 0, !insn.addr !80

; uselistorder directives
  uselistorder i64 (i64)* @function_40, { 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @function_14, { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 12}
!1 = !{i64 16}
!2 = !{i64 48}
!3 = !{i64 60}
!4 = !{i64 64}
!5 = !{i64 92}
!6 = !{i64 100}
!7 = !{i64 108}
!8 = !{i64 116}
!9 = !{i64 120}
!10 = !{i64 132}
!11 = !{i64 136}
!12 = !{i64 140}
!13 = !{i64 144}
!14 = !{i64 148}
!15 = !{i64 152}
!16 = !{i64 160}
!17 = !{i64 164}
!18 = !{i64 184}
!19 = !{i64 216}
!20 = !{i64 224}
!21 = !{i64 232}
!22 = !{i64 240}
!23 = !{i64 244}
!24 = !{i64 248}
!25 = !{i64 252}
!26 = !{i64 264}
!27 = !{i64 268}
!28 = !{i64 272}
!29 = !{i64 280}
!30 = !{i64 284}
!31 = !{i64 288}
!32 = !{i64 296}
!33 = !{i64 300}
!34 = !{i64 312}
!35 = !{i64 324}
!36 = !{i64 292}
!37 = !{i64 320}
!38 = !{i64 344}
!39 = !{i64 352}
!40 = !{i64 384}
!41 = !{i64 388}
!42 = !{i64 392}
!43 = !{i64 400}
!44 = !{i64 408}
!45 = !{i64 412}
!46 = !{i64 420}
!47 = !{i64 424}
!48 = !{i64 428}
!49 = !{i64 432}
!50 = !{i64 436}
!51 = !{i64 452}
!52 = !{i64 456}
!53 = !{i64 460}
!54 = !{i64 468}
!55 = !{i64 480}
!56 = !{i64 484}
!57 = !{i64 488}
!58 = !{i64 492}
!59 = !{i64 496}
!60 = !{i64 504}
!61 = !{i64 512}
!62 = !{i64 528}
!63 = !{i64 536}
!64 = !{i64 544}
!65 = !{i64 548}
!66 = !{i64 552}
!67 = !{i64 568}
!68 = !{i64 576}
!69 = !{i64 588}
!70 = !{i64 596}
!71 = !{i64 612}
!72 = !{i64 620}
!73 = !{i64 628}
!74 = !{i64 632}
!75 = !{i64 640}
!76 = !{i64 648}
!77 = !{i64 660}
!78 = !{i64 664}
!79 = !{i64 668}
!80 = !{i64 684}
