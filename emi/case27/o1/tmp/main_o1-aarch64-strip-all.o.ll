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
  %2 = call i64 @function_40(i64 %1), !insn.addr !5
  %3 = call i64 @function_14(), !insn.addr !6
  %4 = call i64 @function_40(i64 %3), !insn.addr !7
  %5 = call i64 @function_40(i64 %4), !insn.addr !8
  %6 = call i64 @function_40(i64 %5), !insn.addr !9
  %7 = call i64 @function_0(), !insn.addr !10
  %8 = call i64 @function_0(), !insn.addr !11
  %9 = sub i64 %2, %1, !insn.addr !12
  %10 = call i64 @function_0(), !insn.addr !13
  %11 = call i64 @function_0(), !insn.addr !14
  %factor = mul i64 %6, 8589934112
  %reass.add = add i64 %9, %factor
  %reass.mul = mul i64 %reass.add, 2
  %12 = sub i64 %reass.mul, %5, !insn.addr !15
  %13 = and i64 %12, 4294967295, !insn.addr !15
  ret i64 %13, !insn.addr !16

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @function_e4() local_unnamed_addr {
dec_label_pc_e4:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_14(), !insn.addr !17
  %3 = call i64 @function_40(i64 %2), !insn.addr !18
  %4 = call i64 @function_14(), !insn.addr !19
  %5 = call i64 @function_14(), !insn.addr !20
  %6 = call i64 @function_40(i64 %5), !insn.addr !21
  %7 = add i64 %2, %1, !insn.addr !22
  %8 = call i64 @function_0(), !insn.addr !23
  %9 = sub i64 %7, %4, !insn.addr !24
  %10 = add i64 %9, %5, !insn.addr !25
  %11 = mul i64 %10, %3, !insn.addr !26
  %12 = mul i64 %5, %1, !insn.addr !27
  %13 = sub i64 %12, %11, !insn.addr !27
  %14 = and i64 %13, 4294967295, !insn.addr !27
  ret i64 %14, !insn.addr !28

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @function_154() local_unnamed_addr {
dec_label_pc_154:
  %0 = call i64 @function_14(), !insn.addr !29
  %1 = call i64 @function_40(i64 %0), !insn.addr !30
  %2 = call i64 @function_14(), !insn.addr !31
  %3 = call i64 @function_14(), !insn.addr !32
  %4 = call i64 @function_40(i64 %3), !insn.addr !33
  %5 = mul i64 %4, 4294967000, !insn.addr !34
  %6 = add i64 %3, 759, !insn.addr !35
  %7 = add i64 %6, %5, !insn.addr !36
  %8 = call i64 @function_0(), !insn.addr !37
  %9 = sub i64 4294966537, %2, !insn.addr !38
  %10 = add i64 %9, %3, !insn.addr !39
  %11 = sub i64 %10, %5, !insn.addr !40
  %12 = mul i64 %7, %5, !insn.addr !41
  %13 = mul i64 %12, %11, !insn.addr !42
  %14 = and i64 %13, 4294967288, !insn.addr !42
  ret i64 %14, !insn.addr !43

; uselistorder directives
  uselistorder i64 %5, { 1, 0, 2 }
}

define i64 @function_1bc() local_unnamed_addr {
dec_label_pc_1bc:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_14(), !insn.addr !44
  %3 = call i64 @function_40(i64 %2), !insn.addr !45
  %4 = call i64 @function_14(), !insn.addr !46
  %5 = call i64 @function_14(), !insn.addr !47
  %6 = call i64 @function_14(), !insn.addr !48
  %7 = call i64 @function_0(), !insn.addr !49
  %8 = call i64 @function_0(), !insn.addr !50
  %9 = call i64 @function_0(), !insn.addr !51
  %10 = add i64 %1, 4294966178, !insn.addr !52
  %11 = and i64 %10, 4294967295, !insn.addr !52
  ret i64 %11, !insn.addr !53

; uselistorder directives
  uselistorder i64 ()* @function_0, { 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

define i64 @function_240() local_unnamed_addr {
dec_label_pc_240:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_14(), !insn.addr !54
  %3 = call i64 @function_40(i64 %2), !insn.addr !55
  %4 = call i64 @function_40(i64 %3), !insn.addr !56
  %5 = call i64 @function_40(i64 %4), !insn.addr !57
  %6 = call i64 @function_14(), !insn.addr !58
  %7 = mul i64 %1, 4294966625, !insn.addr !59
  %8 = mul i64 %7, %3, !insn.addr !60
  %9 = add i64 %8, %1, !insn.addr !60
  %10 = sub i64 %9, %4, !insn.addr !61
  %11 = and i64 %10, 4294967295, !insn.addr !61
  ret i64 %11, !insn.addr !62

; uselistorder directives
  uselistorder i64 %1, { 1, 0 }
}

define i64 @function_290() local_unnamed_addr {
dec_label_pc_290:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_40(i64 %1), !insn.addr !63
  %3 = call i64 @function_14(), !insn.addr !64
  %4 = call i64 @function_40(i64 %3), !insn.addr !65
  %5 = call i64 @function_40(i64 %4), !insn.addr !66
  %6 = call i64 @function_44(), !insn.addr !67
  %7 = call i64 @function_e4(), !insn.addr !68
  %8 = call i64 @function_154(), !insn.addr !69
  %9 = call i64 @function_1bc(), !insn.addr !70
  %10 = call i64 @function_240(), !insn.addr !71
  ret i64 0, !insn.addr !72

; uselistorder directives
  uselistorder i64 ()* @function_14, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 (i64)* @function_40, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i32 1, { 4, 3, 2, 1, 0, 5 }
}

!0 = !{i64 12}
!1 = !{i64 16}
!2 = !{i64 48}
!3 = !{i64 60}
!4 = !{i64 64}
!5 = !{i64 92}
!6 = !{i64 100}
!7 = !{i64 108}
!8 = !{i64 112}
!9 = !{i64 120}
!10 = !{i64 152}
!11 = !{i64 164}
!12 = !{i64 168}
!13 = !{i64 184}
!14 = !{i64 196}
!15 = !{i64 204}
!16 = !{i64 224}
!17 = !{i64 252}
!18 = !{i64 260}
!19 = !{i64 268}
!20 = !{i64 276}
!21 = !{i64 284}
!22 = !{i64 288}
!23 = !{i64 296}
!24 = !{i64 300}
!25 = !{i64 304}
!26 = !{i64 308}
!27 = !{i64 316}
!28 = !{i64 336}
!29 = !{i64 356}
!30 = !{i64 360}
!31 = !{i64 364}
!32 = !{i64 372}
!33 = !{i64 380}
!34 = !{i64 388}
!35 = !{i64 392}
!36 = !{i64 396}
!37 = !{i64 404}
!38 = !{i64 408}
!39 = !{i64 420}
!40 = !{i64 424}
!41 = !{i64 428}
!42 = !{i64 432}
!43 = !{i64 440}
!44 = !{i64 464}
!45 = !{i64 468}
!46 = !{i64 472}
!47 = !{i64 480}
!48 = !{i64 488}
!49 = !{i64 512}
!50 = !{i64 540}
!51 = !{i64 552}
!52 = !{i64 556}
!53 = !{i64 572}
!54 = !{i64 596}
!55 = !{i64 600}
!56 = !{i64 608}
!57 = !{i64 616}
!58 = !{i64 620}
!59 = !{i64 624}
!60 = !{i64 632}
!61 = !{i64 644}
!62 = !{i64 652}
!63 = !{i64 668}
!64 = !{i64 676}
!65 = !{i64 684}
!66 = !{i64 688}
!67 = !{i64 696}
!68 = !{i64 704}
!69 = !{i64 708}
!70 = !{i64 716}
!71 = !{i64 724}
!72 = !{i64 740}
