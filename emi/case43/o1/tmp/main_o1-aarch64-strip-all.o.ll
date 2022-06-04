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
  %0 = call i64 @function_14(), !insn.addr !5
  %1 = call i64 @function_14(), !insn.addr !6
  %2 = call i64 @function_14(), !insn.addr !7
  %3 = call i64 @function_14(), !insn.addr !8
  %4 = call i64 @function_14(), !insn.addr !9
  %5 = mul i64 %3, %1, !insn.addr !10
  %6 = call i64 @function_0(), !insn.addr !11
  %7 = sub i64 %5, %3, !insn.addr !12
  %8 = and i64 %7, 4294967295, !insn.addr !12
  ret i64 %8, !insn.addr !13

; uselistorder directives
  uselistorder i64 %3, { 1, 0 }
}

define i64 @function_88() local_unnamed_addr {
dec_label_pc_88:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_40(i64 %1), !insn.addr !14
  %3 = call i64 @function_40(i64 %2), !insn.addr !15
  %4 = call i64 @function_14(), !insn.addr !16
  %5 = call i64 @function_14(), !insn.addr !17
  %6 = call i64 @function_40(i64 %5), !insn.addr !18
  %7 = call i64 @function_0(), !insn.addr !19
  %8 = call i64 @function_0(), !insn.addr !20
  %9 = add i64 %5, %3, !insn.addr !21
  %10 = mul i64 %9, %6, !insn.addr !22
  %11 = call i64 @function_0(), !insn.addr !23
  %12 = add i64 %3, 4294967284, !insn.addr !24
  %13 = add i64 %12, %4, !insn.addr !22
  %14 = sub i64 %13, %6, !insn.addr !25
  %15 = add i64 %14, %10, !insn.addr !26
  %16 = and i64 %15, 4294967295, !insn.addr !26
  ret i64 %16, !insn.addr !27

; uselistorder directives
  uselistorder i64 %3, { 1, 0 }
}

define i64 @function_114() local_unnamed_addr {
dec_label_pc_114:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_14(), !insn.addr !28
  %3 = call i64 @function_14(), !insn.addr !29
  %4 = call i64 @function_40(i64 %3), !insn.addr !30
  %5 = call i64 @function_40(i64 %4), !insn.addr !31
  %6 = call i64 @function_40(i64 %5), !insn.addr !32
  %7 = call i64 @function_0(), !insn.addr !33
  %8 = call i64 @function_0(), !insn.addr !34
  %9 = call i64 @function_0(), !insn.addr !35
  %10 = sub i64 770, %1, !insn.addr !36
  %11 = and i64 %10, 4294967295, !insn.addr !36
  ret i64 %11, !insn.addr !37
}

define i64 @function_188() local_unnamed_addr {
dec_label_pc_188:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_40(i64 %1), !insn.addr !38
  %3 = call i64 @function_40(i64 %2), !insn.addr !39
  %4 = call i64 @function_40(i64 %3), !insn.addr !40
  %5 = call i64 @function_40(i64 %4), !insn.addr !41
  %6 = call i64 @function_14(), !insn.addr !42
  %7 = call i64 @function_0(), !insn.addr !43
  %8 = call i64 @function_0(), !insn.addr !44
  %9 = call i64 @function_0(), !insn.addr !45
  %10 = call i64 @function_0(), !insn.addr !46
  %11 = call i64 @function_0(), !insn.addr !47
  %12 = sub i64 %4, %5, !insn.addr !48
  %13 = and i64 %12, 4294967295, !insn.addr !48
  ret i64 %13, !insn.addr !49
}

define i64 @function_230() local_unnamed_addr {
dec_label_pc_230:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = call i64 @function_40(i64 %1), !insn.addr !50
  %3 = call i64 @function_40(i64 %2), !insn.addr !51
  %4 = call i64 @function_14(), !insn.addr !52
  %5 = call i64 @function_14(), !insn.addr !53
  %6 = call i64 @function_14(), !insn.addr !54
  %7 = call i64 @function_0(), !insn.addr !55
  %8 = call i64 @function_0(), !insn.addr !56
  %9 = sub i64 4294966620, %2, !insn.addr !57
  %10 = add i64 %9, %3, !insn.addr !58
  %11 = sub i64 %10, %4, !insn.addr !59
  %12 = add i64 %11, %6, !insn.addr !60
  %13 = and i64 %12, 4294967295, !insn.addr !60
  ret i64 %13, !insn.addr !61

; uselistorder directives
  uselistorder i64 ()* @function_0, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i32 1, { 3, 2, 1, 0, 4 }
}

define i64 @function_2a4() local_unnamed_addr {
dec_label_pc_2a4:
  %0 = call i64 @function_14(), !insn.addr !62
  %1 = call i64 @function_14(), !insn.addr !63
  %2 = call i64 @function_40(i64 %1), !insn.addr !64
  %3 = call i64 @function_14(), !insn.addr !65
  %4 = call i64 @function_44(), !insn.addr !66
  %5 = call i64 @function_88(), !insn.addr !67
  %6 = call i64 @function_114(), !insn.addr !68
  %7 = call i64 @function_188(), !insn.addr !69
  %8 = call i64 @function_230(), !insn.addr !70
  ret i64 0, !insn.addr !71

; uselistorder directives
  uselistorder i64 (i64)* @function_40, { 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
  uselistorder i64 ()* @function_14, { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
}

!0 = !{i64 12}
!1 = !{i64 16}
!2 = !{i64 48}
!3 = !{i64 60}
!4 = !{i64 64}
!5 = !{i64 80}
!6 = !{i64 84}
!7 = !{i64 92}
!8 = !{i64 96}
!9 = !{i64 104}
!10 = !{i64 108}
!11 = !{i64 116}
!12 = !{i64 124}
!13 = !{i64 132}
!14 = !{i64 156}
!15 = !{i64 160}
!16 = !{i64 168}
!17 = !{i64 176}
!18 = !{i64 184}
!19 = !{i64 212}
!20 = !{i64 224}
!21 = !{i64 228}
!22 = !{i64 236}
!23 = !{i64 244}
!24 = !{i64 232}
!25 = !{i64 248}
!26 = !{i64 264}
!27 = !{i64 272}
!28 = !{i64 300}
!29 = !{i64 308}
!30 = !{i64 316}
!31 = !{i64 320}
!32 = !{i64 328}
!33 = !{i64 340}
!34 = !{i64 356}
!35 = !{i64 364}
!36 = !{i64 368}
!37 = !{i64 388}
!38 = !{i64 428}
!39 = !{i64 436}
!40 = !{i64 440}
!41 = !{i64 448}
!42 = !{i64 456}
!43 = !{i64 468}
!44 = !{i64 484}
!45 = !{i64 500}
!46 = !{i64 520}
!47 = !{i64 528}
!48 = !{i64 532}
!49 = !{i64 556}
!50 = !{i64 576}
!51 = !{i64 584}
!52 = !{i64 592}
!53 = !{i64 600}
!54 = !{i64 604}
!55 = !{i64 640}
!56 = !{i64 648}
!57 = !{i64 612}
!58 = !{i64 616}
!59 = !{i64 652}
!60 = !{i64 664}
!61 = !{i64 672}
!62 = !{i64 692}
!63 = !{i64 700}
!64 = !{i64 708}
!65 = !{i64 716}
!66 = !{i64 720}
!67 = !{i64 724}
!68 = !{i64 732}
!69 = !{i64 748}
!70 = !{i64 752}
!71 = !{i64 772}
