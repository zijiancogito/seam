; ModuleID = '/home/caoy/proj/case/case43/main.c'
source_filename = "/home/caoy/proj/case/case43/main.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.str = private unnamed_addr constant [3 x i8] c"%d\00", align 1

; Function Attrs: nofree noinline nounwind uwtable
define dso_local void @f_printf(i32 %p0) local_unnamed_addr #0 {
entry:
  %call = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str, i64 0, i64 0), i32 %p0)
  ret void
}

; Function Attrs: nofree nounwind
declare dso_local i32 @printf(i8* nocapture readonly, ...) local_unnamed_addr #1

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @f_scanf_nop() local_unnamed_addr #2 {
entry:
  %var0 = alloca i32, align 4
  %0 = bitcast i32* %var0 to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %0) #5
  %call = call i32 (i8*, ...) @__isoc99_scanf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str, i64 0, i64 0), i32* nonnull %var0)
  %1 = load i32, i32* %var0, align 4, !tbaa !2
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %0) #5
  ret i32 %1
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #3

; Function Attrs: nofree nounwind
declare dso_local i32 @__isoc99_scanf(i8* nocapture readonly, ...) local_unnamed_addr #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #3

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @f_rand() local_unnamed_addr #2 {
entry:
  %call = tail call i32 (...) @rand() #5
  ret i32 %call
}

declare dso_local i32 @rand(...) local_unnamed_addr #4

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func0() local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_scanf_nop()
  %mul = mul nsw i32 %call3, %call1
  %add7 = add nsw i32 %mul, %call3
  tail call void @f_printf(i32 %add7)
  %sub8 = sub nsw i32 %mul, %call3
  ret i32 %sub8
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func1(i32 %p0, i32 %p1) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_rand()
  %factor = shl i32 %call3, 1
  %add5 = sub i32 %factor, %call2
  %mul = mul nsw i32 %add5, 894
  tail call void @f_printf(i32 %mul)
  %add6 = sub i32 -6, %call4
  %sub7 = add i32 %add6, %mul
  tail call void @f_printf(i32 %sub7)
  %add8 = add nsw i32 %call3, %call1
  %mul9 = mul nsw i32 %add8, %call4
  %add10 = sub i32 %call1, %call4
  %sub11 = add i32 %add10, %mul9
  tail call void @f_printf(i32 %sub11)
  %add13 = add i32 %call2, -12
  %add14 = add i32 %add13, %sub11
  ret i32 %add14
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func2(i32 %p0, i32 %p1) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_rand()
  %add = add nsw i32 %call3, 882
  tail call void @f_printf(i32 %add)
  %sub = sub nsw i32 770, %call
  %mul = mul nsw i32 %sub, %call1
  tail call void @f_printf(i32 %mul)
  %sub5 = sub nsw i32 %call4, %call3
  tail call void @f_printf(i32 %sub5)
  %sub8 = sub nsw i32 770, %p1
  ret i32 %sub8
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func3(i32 %p0, i32 %p1, i32 %p2) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_scanf_nop()
  %add = add nsw i32 %p1, %p0
  tail call void @f_printf(i32 %add)
  %mul = mul nsw i32 %call3, 912
  tail call void @f_printf(i32 %mul)
  %add5 = add nsw i32 %p2, %p1
  %sub = sub i32 %add5, %call3
  %mul6 = mul nsw i32 %sub, %call4
  tail call void @f_printf(i32 %mul6)
  %add7 = add nsw i32 %p2, %p0
  %sub8 = sub i32 %add7, %mul
  %mul9 = mul nsw i32 %sub8, %p1
  %sub10 = sub i32 %call, %call3
  %add11 = add i32 %sub10, %mul9
  tail call void @f_printf(i32 %add11)
  %sub12 = sub nsw i32 %p1, %p2
  tail call void @f_printf(i32 %sub12)
  %sub13 = sub nsw i32 %call2, %call3
  ret i32 %sub13
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func4() local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_scanf_nop()
  %add = add i32 %call1, -338
  %sub = sub i32 %add, %call2
  %sub5 = add i32 %sub, %call4
  %mul = mul i32 %call, 157
  %mul7 = mul i32 %mul, %sub
  %sub8 = add nsw i32 %mul7, -157
  tail call void @f_printf(i32 %sub8)
  %sub9 = sub nsw i32 %sub8, %sub5
  tail call void @f_printf(i32 %sub9)
  %add11.neg = sub i32 -338, %call
  %sub12 = add i32 %add11.neg, %sub5
  ret i32 %sub12
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @func0()
  %call5 = tail call i32 @func1(i32 undef, i32 undef)
  %call6 = tail call i32 @func2(i32 undef, i32 %call1)
  %call7 = tail call i32 @func3(i32 %call, i32 %call1, i32 %call2)
  %call8 = tail call i32 @func4()
  ret i32 0
}

attributes #0 = { nofree noinline nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nofree nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noinline nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { argmemonly nounwind }
attributes #4 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #5 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0 "}
!2 = !{!3, !3, i64 0}
!3 = !{!"int", !4, i64 0}
!4 = !{!"omnipotent char", !5, i64 0}
!5 = !{!"Simple C/C++ TBAA"}
