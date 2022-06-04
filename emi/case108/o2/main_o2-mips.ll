; ModuleID = '/home/caoy/proj/case/case108/main.c'
source_filename = "/home/caoy/proj/case/case108/main.c"
target datalayout = "E-m:m-p:32:32-i8:8:32-i16:16:32-i64:64-n32-S64"
target triple = "mips"

@.str = private unnamed_addr constant [3 x i8] c"%d\00", align 1

; Function Attrs: nofree noinline nounwind
define dso_local void @f_printf(i32 signext %p0) local_unnamed_addr #0 {
entry:
  %call = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str, i32 0, i32 0), i32 signext %p0)
  ret void
}

; Function Attrs: nofree nounwind
declare dso_local i32 @printf(i8* nocapture readonly, ...) local_unnamed_addr #1

; Function Attrs: noinline nounwind
define dso_local i32 @f_scanf_nop() local_unnamed_addr #2 {
entry:
  %var0 = alloca i32, align 4
  %0 = bitcast i32* %var0 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %0) #5
  %call = call i32 (i8*, ...) @__isoc99_scanf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str, i32 0, i32 0), i32* nonnull %var0) #5
  %1 = load i32, i32* %var0, align 4, !tbaa !2
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %0) #5
  ret i32 %1
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #3

declare dso_local i32 @__isoc99_scanf(i8*, ...) local_unnamed_addr #4

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #3

; Function Attrs: noinline nounwind
define dso_local i32 @f_rand() local_unnamed_addr #2 {
entry:
  %call = tail call i32 bitcast (i32 (...)* @rand to i32 ()*)() #5
  ret i32 %call
}

declare dso_local i32 @rand(...) local_unnamed_addr #4

; Function Attrs: noinline nounwind
define dso_local i32 @func0(i32 signext %p0, i32 signext %p1) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_rand()
  %mul = mul nsw i32 %call4, %call
  tail call void @f_printf(i32 signext %mul)
  %add = add nsw i32 %call, %p0
  %add5 = add nsw i32 %add, %call4
  %mul6 = mul nsw i32 %add5, %call1
  %add7 = sub i32 %p0, %call1
  %sub = add i32 %add7, %mul6
  tail call void @f_printf(i32 signext %add7)
  %sub10 = sub nsw i32 %call4, %call2
  tail call void @f_printf(i32 signext %sub10)
  %mul11 = mul nsw i32 %sub, %call2
  ret i32 %mul11
}

; Function Attrs: noinline nounwind
define dso_local i32 @func1(i32 signext %p0) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_rand()
  %mul = mul nsw i32 %call2, %call
  %add = add nsw i32 %mul, %call1
  tail call void @f_printf(i32 signext %add)
  %add5 = add i32 %call2, %call1
  %add6 = add i32 %add5, %call4
  tail call void @f_printf(i32 signext %add6)
  %mul7 = mul i32 %add6, %call4
  %mul8 = mul i32 %mul7, %call
  %mul9 = mul i32 %mul8, %add
  %add12 = add nsw i32 %call, %p0
  %add13 = add nsw i32 %add12, %add
  %mul14 = mul nsw i32 %add13, %p0
  tail call void @f_printf(i32 signext %mul14)
  %mul16 = mul i32 %mul7, %mul
  %sub17 = sub nsw i32 %mul16, %mul9
  %mul18 = mul nsw i32 %sub17, %mul
  %add19 = sub i32 %mul14, %add
  %sub20 = add i32 %add19, %mul18
  ret i32 %sub20
}

; Function Attrs: noinline nounwind
define dso_local i32 @func2(i32 signext %p0, i32 signext %p1) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_rand()
  %add = add nsw i32 %call2, 508
  tail call void @f_printf(i32 signext %add)
  %sub = sub i32 %p0, %call2
  %sub5 = sub i32 %sub, %call3
  %sub6 = add nsw i32 %p1, 583
  %mul = mul i32 %sub6, %p0
  %mul7 = mul i32 %mul, %add
  %add8 = add nsw i32 %mul7, %add
  %mul10 = mul nsw i32 %add8, %mul7
  %add11 = add nsw i32 %sub5, %mul10
  ret i32 %add11
}

; Function Attrs: noinline nounwind
define dso_local i32 @func3() local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_rand()
  %sub8 = sub nsw i32 498, %call4
  ret i32 %sub8
}

; Function Attrs: noinline nounwind
define dso_local i32 @func4(i32 signext %p0) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_rand()
  %sub = sub i32 -604, %call
  tail call void @f_printf(i32 signext %sub)
  tail call void @f_printf(i32 signext %sub)
  %sub10 = mul i32 %call1, -7853
  ret i32 %sub10
}

; Function Attrs: noinline nounwind
define dso_local i32 @main() local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @func0(i32 signext %call, i32 signext undef)
  %call5 = tail call i32 @func1(i32 signext %call)
  %call6 = tail call i32 @func2(i32 signext %call, i32 signext %call1)
  %call7 = tail call i32 @func3()
  %call8 = tail call i32 @func4(i32 signext undef)
  ret i32 0
}

attributes #0 = { nofree noinline nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="mips32r2" "target-features"="+mips32r2,-noabicalls" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nofree nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="mips32r2" "target-features"="+mips32r2,-noabicalls" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noinline nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="mips32r2" "target-features"="+mips32r2,-noabicalls" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { argmemonly nounwind }
attributes #4 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="mips32r2" "target-features"="+mips32r2,-noabicalls" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #5 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0 "}
!2 = !{!3, !3, i64 0}
!3 = !{!"int", !4, i64 0}
!4 = !{!"omnipotent char", !5, i64 0}
!5 = !{!"Simple C/C++ TBAA"}
