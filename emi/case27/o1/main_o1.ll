; ModuleID = '/home/caoy/proj/case/case27/main.c'
source_filename = "/home/caoy/proj/case/case27/main.c"
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
define dso_local i32 @func0(i32 %p0) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_rand()
  %p0.neg = shl i32 %p0, 1
  %add = sub i32 -240, %p0.neg
  %sub5 = add i32 %add, %call1
  %mul = mul i32 %p0, -240
  %mul6 = mul i32 %mul, %sub5
  %sub7 = add nsw i32 %mul6, 342
  tail call void @f_printf(i32 %sub7)
  %mul8 = mul nsw i32 %call4, -240
  tail call void @f_printf(i32 %mul8)
  %add9 = sub i32 %call, %p0
  %sub10 = add i32 %add9, %mul8
  %sub11 = sub nsw i32 %sub10, %call3
  tail call void @f_printf(i32 %sub11)
  %add12 = add nsw i32 %sub11, %mul8
  %mul13 = mul nsw i32 %add12, %mul8
  tail call void @f_printf(i32 %mul13)
  %add14 = add i32 %sub10, %mul8
  %add15 = add nsw i32 %add14, %add12
  ret i32 %add15
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func1(i32 %p0) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_rand()
  %add = add nsw i32 %call, %p0
  tail call void @f_printf(i32 %add)
  %sub6 = sub i32 %add, %call2
  %add7 = add i32 %sub6, %call3
  %mul = mul nsw i32 %add7, %call1
  %mul8 = mul nsw i32 %call3, %p0
  %sub11 = sub nsw i32 %mul8, %mul
  ret i32 %sub11
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func2() local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_rand()
  %mul = mul nsw i32 %call4, -296
  %add10 = add i32 %call3, 759
  %add11 = add nsw i32 %add10, %mul
  tail call void @f_printf(i32 %add11)
  %sub12 = sub i32 -759, %call2
  %sub13 = add i32 %sub12, %call3
  %sub14 = sub i32 %sub13, %mul
  %mul15 = mul i32 %add11, %mul
  %mul16 = mul i32 %mul15, %sub14
  ret i32 %mul16
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func3(i32 %p0) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_scanf_nop()
  %call3 = tail call i32 @f_scanf_nop()
  %call4 = tail call i32 @f_scanf_nop()
  %add = add nsw i32 %call2, %p0
  %sub = add nsw i32 %p0, -485
  %mul = mul nsw i32 %add, %sub
  %sub5 = sub nsw i32 %mul, %call4
  tail call void @f_printf(i32 %sub5)
  %add6 = add nsw i32 %p0, 148
  %sub7 = sub i32 %add6, %add
  %sub8 = sub i32 %sub7, %call3
  %sub9 = sub i32 %sub8, %call4
  %mul10 = mul nsw i32 %sub9, %p0
  %sub11 = add nsw i32 %mul10, -485
  tail call void @f_printf(i32 %sub11)
  %sub12 = sub nsw i32 633, %p0
  tail call void @f_printf(i32 %sub12)
  %sub13 = add nsw i32 %p0, -1118
  ret i32 %sub13
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @func4(i32 %p0, i32 %p1) local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_scanf_nop()
  %call1 = tail call i32 @f_rand()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @f_scanf_nop()
  %mul = mul i32 %p1, -671
  %mul5 = mul i32 %mul, %call1
  %add = add nsw i32 %mul5, %p1
  %sub13 = sub i32 %add, %call2
  ret i32 %sub13
}

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() local_unnamed_addr #2 {
entry:
  %call = tail call i32 @f_rand()
  %call1 = tail call i32 @f_scanf_nop()
  %call2 = tail call i32 @f_rand()
  %call3 = tail call i32 @f_rand()
  %call4 = tail call i32 @func0(i32 %call)
  %call5 = tail call i32 @func1(i32 %call)
  %call6 = tail call i32 @func2()
  %call7 = tail call i32 @func3(i32 %call)
  %call8 = tail call i32 @func4(i32 undef, i32 %call1)
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
