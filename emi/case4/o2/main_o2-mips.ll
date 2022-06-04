; ModuleID = '/home/caoy/proj/case/case4/main.c'
source_filename = "/home/caoy/proj/case/case4/main.c"
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
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_rand()
  %factor = shl i32 %p0, 1
  %add = sub i32 %factor, %p1
  %sub7 = sub i32 %add, %call2
  %0 = mul i32 %sub7, 700
  %sub13 = add i32 %call4, %call3
  %add14 = add i32 %sub13, %0
  %mul15 = mul nsw i32 %add14, %call4
  %add16 = add nsw i32 %mul15, %call3
  ret i32 %add16
}

; Function Attrs: noinline nounwind
define dso_local i32 @func1(i32 signext %p0, i32 signext %p1) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_scanf_nop()
  %add = add nsw i32 %call3, %p1
  %mul = mul nsw i32 %add, %call
  %sub7 = add nsw i32 %mul, 348
  tail call void @f_printf(i32 signext %sub7)
  %sub8 = sub nsw i32 -233, %p1
  tail call void @f_printf(i32 signext %sub8)
  %sub10 = add nsw i32 %call, 233
  ret i32 %sub10
}

; Function Attrs: noinline nounwind
define dso_local i32 @func2(i32 signext %p0) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_rand()
  %mul = mul nsw i32 %call, -619
  %mul5 = mul nsw i32 %mul, %call2
  %add = add nsw i32 %mul5, %call1
  tail call void @f_printf(i32 signext %add)
  %add6 = add nsw i32 %call1, -619
  %mul7 = mul nsw i32 %call3, %add6
  %add8 = sub i32 %call2, %call3
  %sub = add i32 %add8, %add
  tail call void @f_printf(i32 signext %sub)
  %sub9 = sub nsw i32 %call2, %add
  %mul10 = mul nsw i32 %sub9, %call1
  %add14 = add nsw i32 %mul10, %mul7
  ret i32 %add14
}

; Function Attrs: noinline nounwind
define dso_local i32 @func3(i32 signext %p0) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_rand()
  %mul = mul nsw i32 %call, 737
  %add = add nsw i32 %call3, %mul
  tail call void @f_printf(i32 signext %add)
  %add5 = add nsw i32 %call, -94
  tail call void @f_printf(i32 signext %add5)
  %add6 = add nsw i32 %call2, %call1
  tail call void @f_printf(i32 signext %add6)
  %mul9 = mul nsw i32 %add, %call
  %sub10 = sub i32 %add, %call4
  %add11 = add i32 %sub10, %mul9
  %mul12 = mul nsw i32 %call4, -94
  %mul13 = mul nsw i32 %mul12, %add11
  %add14 = add nsw i32 %mul13, %call4
  ret i32 %add14
}

; Function Attrs: noinline nounwind
define dso_local i32 @func4(i32 signext %p0, i32 signext %p1, i32 signext %p2) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_rand()
  %sub = sub nsw i32 %call1, %p2
  tail call void @f_printf(i32 signext %sub)
  %sub6 = add nsw i32 %sub, -849
  %mul = mul nsw i32 %sub6, %call3
  %mul12 = mul nsw i32 %sub, 849
  %sub13 = sub nsw i32 %mul12, %p1
  tail call void @f_printf(i32 signext %sub13)
  %0 = add i32 %call2, %p2
  %sub8 = sub i32 %sub, %0
  %add9 = add i32 %sub8, %call3
  %add14 = add i32 %add9, %mul
  ret i32 %add14
}

; Function Attrs: noinline nounwind
define dso_local i32 @main() local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @func0(i32 signext %call, i32 signext %call1)
  %call5 = tail call i32 @func1(i32 signext undef, i32 signext %call1)
  %call6 = tail call i32 @func2(i32 signext undef)
  %call7 = tail call i32 @func3(i32 signext %call)
  %call8 = tail call i32 @func4(i32 signext undef, i32 signext %call1, i32 signext %call2)
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
