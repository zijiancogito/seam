; ModuleID = 'main.c'
source_filename = "main.c"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "aarch64"

@.str = private unnamed_addr constant [7 x i8] c"%d%d%d\00", align 1
@x = common dso_local global i32 0, align 4
@.str.1 = private unnamed_addr constant [10 x i8] c"%d %d %d\0A\00", align 1

; Function Attrs: nounwind
define dso_local i32 @main() local_unnamed_addr #0 {
entry:
  %y = alloca i32, align 4
  %z = alloca i32, align 4
  %0 = bitcast i32* %y to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %0) #4
  %1 = bitcast i32* %z to i8*
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %1) #4
  %call = call i32 (i8*, ...) @__isoc99_scanf(i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i64 0, i64 0), i32* nonnull @x, i32* nonnull %y, i32* nonnull %z) #4
  %2 = load i32, i32* @x, align 4, !tbaa !2
  %3 = load i32, i32* %y, align 4, !tbaa !2
  %cmp = icmp sgt i32 %2, %3
  br i1 %cmp, label %if.then, label %if.end

if.then:                                          ; preds = %entry
  store i32 %3, i32* @x, align 4, !tbaa !2
  store i32 %2, i32* %y, align 4, !tbaa !2
  br label %if.end

if.end:                                           ; preds = %if.then, %entry
  %4 = load i32, i32* @x, align 4, !tbaa !2
  %5 = load i32, i32* %z, align 4, !tbaa !2
  %cmp1 = icmp sgt i32 %4, %5
  br i1 %cmp1, label %if.then2, label %if.end3

if.then2:                                         ; preds = %if.end
  store i32 %4, i32* %z, align 4, !tbaa !2
  store i32 %5, i32* @x, align 4, !tbaa !2
  br label %if.end3

if.end3:                                          ; preds = %if.then2, %if.end
  %6 = load i32, i32* %y, align 4, !tbaa !2
  %7 = load i32, i32* %z, align 4, !tbaa !2
  %cmp4 = icmp sgt i32 %6, %7
  br i1 %cmp4, label %if.then5, label %if.end6

if.then5:                                         ; preds = %if.end3
  store i32 %7, i32* %y, align 4, !tbaa !2
  store i32 %6, i32* %z, align 4, !tbaa !2
  br label %if.end6

if.end6:                                          ; preds = %if.then5, %if.end3
  %8 = load i32, i32* @x, align 4, !tbaa !2
  %9 = load i32, i32* %y, align 4, !tbaa !2
  %10 = load i32, i32* %z, align 4, !tbaa !2
  %call7 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str.1, i64 0, i64 0), i32 %8, i32 %9, i32 %10)
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %1) #4
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %0) #4
  ret i32 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

declare dso_local i32 @__isoc99_scanf(i8*, ...) local_unnamed_addr #2

; Function Attrs: nofree nounwind
declare dso_local i32 @printf(i8* nocapture readonly, ...) local_unnamed_addr #3

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

attributes #0 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }
attributes #2 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nofree nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #4 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0 "}
!2 = !{!3, !3, i64 0}
!3 = !{!"int", !4, i64 0}
!4 = !{!"omnipotent char", !5, i64 0}
!5 = !{!"Simple C/C++ TBAA"}
