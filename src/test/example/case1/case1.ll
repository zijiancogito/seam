; ModuleID = 'case1.c'
source_filename = "case1.c"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "aarch64"

@.str = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1
@.str.1 = private unnamed_addr constant [6 x i8] c"pause\00", align 1

; Function Attrs: nounwind
define dso_local i32 @main() local_unnamed_addr #0 {
entry:
  %T = alloca [50 x i8], align 1
  %P = alloca [10 x i8], align 1
  %0 = getelementptr inbounds [50 x i8], [50 x i8]* %T, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 50, i8* nonnull %0) #6
  %1 = getelementptr inbounds [10 x i8], [10 x i8]* %P, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 10, i8* nonnull %1) #6
  %call = call i32 bitcast (i32 (...)* @gets to i32 (i8*)*)(i8* nonnull %0) #6
  %call2 = call i32 bitcast (i32 (...)* @gets to i32 (i8*)*)(i8* nonnull %1) #6
  %call4 = call i64 @strlen(i8* nonnull %0) #7
  %conv = trunc i64 %call4 to i32
  %call6 = call i64 @strlen(i8* nonnull %1) #7
  %conv7 = trunc i64 %call6 to i32
  %cmp47 = icmp slt i32 %conv, %conv7
  br i1 %cmp47, label %for.end25, label %for.cond9.preheader.lr.ph

for.cond9.preheader.lr.ph:                        ; preds = %entry
  %cmp1043 = icmp sgt i32 %conv7, 0
  %2 = add i64 %call4, 1
  %3 = sub i64 %2, %call6
  %wide.trip.count56 = and i64 %3, 4294967295
  %wide.trip.count = and i64 %call6, 4294967295
  br label %for.cond9.preheader

for.cond9.preheader:                              ; preds = %for.end, %for.cond9.preheader.lr.ph
  %indvars.iv52 = phi i64 [ %indvars.iv.next53, %for.end ], [ 0, %for.cond9.preheader.lr.ph ]
  %count.050 = phi i32 [ %spec.select, %for.end ], [ 0, %for.cond9.preheader.lr.ph ]
  br i1 %cmp1043, label %land.rhs, label %for.end

land.rhs:                                         ; preds = %for.cond9.preheader, %for.inc
  %indvars.iv54 = phi i64 [ %indvars.iv.next55, %for.inc ], [ %indvars.iv52, %for.cond9.preheader ]
  %indvars.iv = phi i64 [ %indvars.iv.next, %for.inc ], [ 0, %for.cond9.preheader ]
  %j.045 = phi i32 [ %inc, %for.inc ], [ 0, %for.cond9.preheader ]
  %arrayidx = getelementptr inbounds [10 x i8], [10 x i8]* %P, i64 0, i64 %indvars.iv
  %4 = load i8, i8* %arrayidx, align 1, !tbaa !2
  %arrayidx14 = getelementptr inbounds [50 x i8], [50 x i8]* %T, i64 0, i64 %indvars.iv54
  %5 = load i8, i8* %arrayidx14, align 1, !tbaa !2
  %cmp16 = icmp eq i8 %4, %5
  br i1 %cmp16, label %for.inc, label %for.end.loopexit.split.loop.exit58

for.inc:                                          ; preds = %land.rhs
  %indvars.iv.next = add nuw nsw i64 %indvars.iv, 1
  %inc = add nuw nsw i32 %j.045, 1
  %indvars.iv.next55 = add nuw nsw i64 %indvars.iv54, 1
  %exitcond = icmp eq i64 %indvars.iv.next, %wide.trip.count
  br i1 %exitcond, label %for.end, label %land.rhs

for.end.loopexit.split.loop.exit58:               ; preds = %land.rhs
  %6 = trunc i64 %indvars.iv to i32
  br label %for.end

for.end:                                          ; preds = %for.inc, %for.end.loopexit.split.loop.exit58, %for.cond9.preheader
  %j.0.lcssa = phi i32 [ 0, %for.cond9.preheader ], [ %6, %for.end.loopexit.split.loop.exit58 ], [ %inc, %for.inc ]
  %cmp20 = icmp eq i32 %j.0.lcssa, %conv7
  %inc22 = zext i1 %cmp20 to i32
  %spec.select = add nuw nsw i32 %count.050, %inc22
  %indvars.iv.next53 = add nuw nsw i64 %indvars.iv52, 1
  %exitcond57 = icmp eq i64 %indvars.iv.next53, %wide.trip.count56
  br i1 %exitcond57, label %for.end25, label %for.cond9.preheader

for.end25:                                        ; preds = %for.end, %entry
  %count.0.lcssa = phi i32 [ 0, %entry ], [ %spec.select, %for.end ]
  %call26 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str, i64 0, i64 0), i32 %count.0.lcssa)
  %call27 = call i32 @system(i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i64 0, i64 0)) #6
  call void @llvm.lifetime.end.p0i8(i64 10, i8* nonnull %1) #6
  call void @llvm.lifetime.end.p0i8(i64 50, i8* nonnull %0) #6
  ret i32 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

declare dso_local i32 @gets(...) local_unnamed_addr #2

; Function Attrs: argmemonly nofree nounwind readonly
declare dso_local i64 @strlen(i8* nocapture) local_unnamed_addr #3

; Function Attrs: nofree nounwind
declare dso_local i32 @printf(i8* nocapture readonly, ...) local_unnamed_addr #4

; Function Attrs: nofree
declare dso_local i32 @system(i8* nocapture readonly) local_unnamed_addr #5

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

attributes #0 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }
attributes #2 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { argmemonly nofree nounwind readonly "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #4 = { nofree nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #5 = { nofree "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #6 = { nounwind }
attributes #7 = { nounwind readonly }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0 "}
!2 = !{!3, !3, i64 0}
!3 = !{!"omnipotent char", !4, i64 0}
!4 = !{!"Simple C/C++ TBAA"}
