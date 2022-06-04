; ModuleID = '/home/caoy/proj/case/case27/main.c'
source_filename = "/home/caoy/proj/case/case27/main.c"
target datalayout = "E-m:m-p:32:32-i8:8:32-i16:16:32-i64:64-n32-S64"
target triple = "mips"

@.str = private unnamed_addr constant [3 x i8] c"%d\00", align 1

; Function Attrs: noinline nounwind optnone
define dso_local void @f_printf(i32 signext %p0) #0 {
entry:
  %p0.addr = alloca i32, align 4
  store i32 %p0, i32* %p0.addr, align 4
  %0 = load i32, i32* %p0.addr, align 4
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str, i32 0, i32 0), i32 signext %0)
  ret void
}

declare dso_local i32 @printf(i8*, ...) #1

; Function Attrs: noinline nounwind optnone
define dso_local i32 @f_scanf_nop() #0 {
entry:
  %var0 = alloca i32, align 4
  %call = call i32 (i8*, ...) @__isoc99_scanf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str, i32 0, i32 0), i32* %var0)
  %0 = load i32, i32* %var0, align 4
  ret i32 %0
}

declare dso_local i32 @__isoc99_scanf(i8*, ...) #1

; Function Attrs: noinline nounwind optnone
define dso_local i32 @f_rand() #0 {
entry:
  %var0 = alloca i32, align 4
  %call = call i32 bitcast (i32 (...)* @rand to i32 ()*)()
  store i32 %call, i32* %var0, align 4
  %0 = load i32, i32* %var0, align 4
  ret i32 %0
}

declare dso_local i32 @rand(...) #1

; Function Attrs: noinline nounwind optnone
define dso_local i32 @func0(i32 signext %p0) #0 {
entry:
  %p0.addr = alloca i32, align 4
  %var0 = alloca i32, align 4
  %var1 = alloca i32, align 4
  %var2 = alloca i32, align 4
  %var3 = alloca i32, align 4
  %var4 = alloca i32, align 4
  %var5 = alloca i32, align 4
  %var6 = alloca i32, align 4
  store i32 %p0, i32* %p0.addr, align 4
  %call = call i32 @f_rand()
  store i32 %call, i32* %var0, align 4
  %call1 = call i32 @f_scanf_nop()
  store i32 %call1, i32* %var1, align 4
  %call2 = call i32 @f_rand()
  store i32 %call2, i32* %var2, align 4
  %call3 = call i32 @f_rand()
  store i32 %call3, i32* %var3, align 4
  %call4 = call i32 @f_rand()
  store i32 %call4, i32* %var4, align 4
  store i32 -342, i32* %var5, align 4
  store i32 -240, i32* %var6, align 4
  %0 = load i32, i32* %var6, align 4
  %1 = load i32, i32* %p0.addr, align 4
  %sub = sub nsw i32 %0, %1
  %2 = load i32, i32* %var1, align 4
  %add = add nsw i32 %sub, %2
  %3 = load i32, i32* %p0.addr, align 4
  %sub5 = sub nsw i32 %add, %3
  %4 = load i32, i32* %var6, align 4
  %mul = mul nsw i32 %sub5, %4
  %5 = load i32, i32* %p0.addr, align 4
  %mul6 = mul nsw i32 %mul, %5
  %6 = load i32, i32* %var5, align 4
  %sub7 = sub nsw i32 %mul6, %6
  store i32 %sub7, i32* %var2, align 4
  %7 = load i32, i32* %var2, align 4
  call void @f_printf(i32 signext %7)
  %8 = load i32, i32* %var6, align 4
  %9 = load i32, i32* %var4, align 4
  %mul8 = mul nsw i32 %8, %9
  store i32 %mul8, i32* %var4, align 4
  %10 = load i32, i32* %var4, align 4
  call void @f_printf(i32 signext %10)
  %11 = load i32, i32* %var4, align 4
  %12 = load i32, i32* %var0, align 4
  %add9 = add nsw i32 %11, %12
  %13 = load i32, i32* %p0.addr, align 4
  %sub10 = sub nsw i32 %add9, %13
  %14 = load i32, i32* %var3, align 4
  %sub11 = sub nsw i32 %sub10, %14
  store i32 %sub11, i32* %var1, align 4
  %15 = load i32, i32* %var1, align 4
  call void @f_printf(i32 signext %15)
  %16 = load i32, i32* %var1, align 4
  %17 = load i32, i32* %var4, align 4
  %add12 = add nsw i32 %16, %17
  store i32 %add12, i32* %p0.addr, align 4
  %18 = load i32, i32* %var4, align 4
  %19 = load i32, i32* %p0.addr, align 4
  %mul13 = mul nsw i32 %18, %19
  store i32 %mul13, i32* %var0, align 4
  %20 = load i32, i32* %var0, align 4
  call void @f_printf(i32 signext %20)
  %21 = load i32, i32* %p0.addr, align 4
  %22 = load i32, i32* %var3, align 4
  %add14 = add nsw i32 %21, %22
  %23 = load i32, i32* %p0.addr, align 4
  %add15 = add nsw i32 %add14, %23
  store i32 %add15, i32* %var4, align 4
  %24 = load i32, i32* %var4, align 4
  ret i32 %24
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @func1(i32 signext %p0) #0 {
entry:
  %p0.addr = alloca i32, align 4
  %var0 = alloca i32, align 4
  %var1 = alloca i32, align 4
  %var2 = alloca i32, align 4
  %var3 = alloca i32, align 4
  %var4 = alloca i32, align 4
  %var5 = alloca i32, align 4
  %var6 = alloca i32, align 4
  store i32 %p0, i32* %p0.addr, align 4
  %call = call i32 @f_scanf_nop()
  store i32 %call, i32* %var0, align 4
  %call1 = call i32 @f_rand()
  store i32 %call1, i32* %var1, align 4
  %call2 = call i32 @f_scanf_nop()
  store i32 %call2, i32* %var2, align 4
  %call3 = call i32 @f_scanf_nop()
  store i32 %call3, i32* %var3, align 4
  %call4 = call i32 @f_rand()
  store i32 %call4, i32* %var4, align 4
  store i32 -893, i32* %var5, align 4
  store i32 -525, i32* %var6, align 4
  %0 = load i32, i32* %p0.addr, align 4
  %1 = load i32, i32* %var0, align 4
  %add = add nsw i32 %0, %1
  store i32 %add, i32* %var6, align 4
  %2 = load i32, i32* %var6, align 4
  call void @f_printf(i32 signext %2)
  %3 = load i32, i32* %p0.addr, align 4
  %4 = load i32, i32* %var3, align 4
  %sub = sub nsw i32 %3, %4
  %5 = load i32, i32* %var2, align 4
  %add5 = add nsw i32 %sub, %5
  store i32 %add5, i32* %var0, align 4
  %6 = load i32, i32* %p0.addr, align 4
  %7 = load i32, i32* %var0, align 4
  %sub6 = sub nsw i32 %6, %7
  %8 = load i32, i32* %var6, align 4
  %add7 = add nsw i32 %sub6, %8
  %9 = load i32, i32* %var1, align 4
  %mul = mul nsw i32 %add7, %9
  store i32 %mul, i32* %var0, align 4
  %10 = load i32, i32* %var3, align 4
  %11 = load i32, i32* %p0.addr, align 4
  %mul8 = mul nsw i32 %10, %11
  store i32 %mul8, i32* %var5, align 4
  %12 = load i32, i32* %var0, align 4
  %13 = load i32, i32* %var3, align 4
  %sub9 = sub nsw i32 %12, %13
  %14 = load i32, i32* %var1, align 4
  %add10 = add nsw i32 %sub9, %14
  store i32 %add10, i32* %var4, align 4
  %15 = load i32, i32* %var5, align 4
  %16 = load i32, i32* %var0, align 4
  %sub11 = sub nsw i32 %15, %16
  store i32 %sub11, i32* %var4, align 4
  %17 = load i32, i32* %var4, align 4
  ret i32 %17
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @func2() #0 {
entry:
  %var0 = alloca i32, align 4
  %var1 = alloca i32, align 4
  %var2 = alloca i32, align 4
  %var3 = alloca i32, align 4
  %var4 = alloca i32, align 4
  %var5 = alloca i32, align 4
  %var6 = alloca i32, align 4
  %call = call i32 @f_scanf_nop()
  store i32 %call, i32* %var0, align 4
  %call1 = call i32 @f_rand()
  store i32 %call1, i32* %var1, align 4
  %call2 = call i32 @f_scanf_nop()
  store i32 %call2, i32* %var2, align 4
  %call3 = call i32 @f_scanf_nop()
  store i32 %call3, i32* %var3, align 4
  %call4 = call i32 @f_rand()
  store i32 %call4, i32* %var4, align 4
  store i32 759, i32* %var5, align 4
  store i32 -296, i32* %var6, align 4
  %0 = load i32, i32* %var4, align 4
  %1 = load i32, i32* %var6, align 4
  %mul = mul nsw i32 %0, %1
  store i32 %mul, i32* %var0, align 4
  %2 = load i32, i32* %var6, align 4
  %3 = load i32, i32* %var4, align 4
  %sub = sub nsw i32 %2, %3
  store i32 %sub, i32* %var1, align 4
  %4 = load i32, i32* %var1, align 4
  %5 = load i32, i32* %var0, align 4
  %mul5 = mul nsw i32 %4, %5
  store i32 %mul5, i32* %var6, align 4
  %6 = load i32, i32* %var1, align 4
  %7 = load i32, i32* %var2, align 4
  %sub6 = sub nsw i32 %6, %7
  %8 = load i32, i32* %var4, align 4
  %mul7 = mul nsw i32 %sub6, %8
  %9 = load i32, i32* %var3, align 4
  %mul8 = mul nsw i32 %mul7, %9
  store i32 %mul8, i32* %var1, align 4
  %10 = load i32, i32* %var3, align 4
  %11 = load i32, i32* %var1, align 4
  %sub9 = sub nsw i32 %10, %11
  %12 = load i32, i32* %var5, align 4
  %add = add nsw i32 %sub9, %12
  %13 = load i32, i32* %var1, align 4
  %add10 = add nsw i32 %add, %13
  %14 = load i32, i32* %var0, align 4
  %add11 = add nsw i32 %add10, %14
  store i32 %add11, i32* %var6, align 4
  %15 = load i32, i32* %var6, align 4
  call void @f_printf(i32 signext %15)
  %16 = load i32, i32* %var3, align 4
  %17 = load i32, i32* %var2, align 4
  %sub12 = sub nsw i32 %16, %17
  %18 = load i32, i32* %var5, align 4
  %sub13 = sub nsw i32 %sub12, %18
  %19 = load i32, i32* %var0, align 4
  %sub14 = sub nsw i32 %sub13, %19
  %20 = load i32, i32* %var6, align 4
  %mul15 = mul nsw i32 %sub14, %20
  %21 = load i32, i32* %var0, align 4
  %mul16 = mul nsw i32 %mul15, %21
  store i32 %mul16, i32* %var0, align 4
  %22 = load i32, i32* %var0, align 4
  ret i32 %22
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @func3(i32 signext %p0) #0 {
entry:
  %p0.addr = alloca i32, align 4
  %var0 = alloca i32, align 4
  %var1 = alloca i32, align 4
  %var2 = alloca i32, align 4
  %var3 = alloca i32, align 4
  %var4 = alloca i32, align 4
  %var5 = alloca i32, align 4
  %var6 = alloca i32, align 4
  store i32 %p0, i32* %p0.addr, align 4
  %call = call i32 @f_scanf_nop()
  store i32 %call, i32* %var0, align 4
  %call1 = call i32 @f_rand()
  store i32 %call1, i32* %var1, align 4
  %call2 = call i32 @f_scanf_nop()
  store i32 %call2, i32* %var2, align 4
  %call3 = call i32 @f_scanf_nop()
  store i32 %call3, i32* %var3, align 4
  %call4 = call i32 @f_scanf_nop()
  store i32 %call4, i32* %var4, align 4
  store i32 633, i32* %var5, align 4
  store i32 485, i32* %var6, align 4
  %0 = load i32, i32* %p0.addr, align 4
  %1 = load i32, i32* %var2, align 4
  %add = add nsw i32 %0, %1
  store i32 %add, i32* %var1, align 4
  %2 = load i32, i32* %p0.addr, align 4
  %3 = load i32, i32* %var6, align 4
  %sub = sub nsw i32 %2, %3
  store i32 %sub, i32* %var0, align 4
  %4 = load i32, i32* %var0, align 4
  %5 = load i32, i32* %var1, align 4
  %mul = mul nsw i32 %4, %5
  %6 = load i32, i32* %var4, align 4
  %sub5 = sub nsw i32 %mul, %6
  store i32 %sub5, i32* %var2, align 4
  %7 = load i32, i32* %var2, align 4
  call void @f_printf(i32 signext %7)
  %8 = load i32, i32* %var0, align 4
  %9 = load i32, i32* %var5, align 4
  %add6 = add nsw i32 %8, %9
  %10 = load i32, i32* %var4, align 4
  %sub7 = sub nsw i32 %add6, %10
  %11 = load i32, i32* %var1, align 4
  %sub8 = sub nsw i32 %sub7, %11
  %12 = load i32, i32* %var3, align 4
  %sub9 = sub nsw i32 %sub8, %12
  %13 = load i32, i32* %p0.addr, align 4
  %mul10 = mul nsw i32 %sub9, %13
  %14 = load i32, i32* %var6, align 4
  %sub11 = sub nsw i32 %mul10, %14
  store i32 %sub11, i32* %var4, align 4
  %15 = load i32, i32* %var4, align 4
  call void @f_printf(i32 signext %15)
  %16 = load i32, i32* %var5, align 4
  %17 = load i32, i32* %p0.addr, align 4
  %sub12 = sub nsw i32 %16, %17
  store i32 %sub12, i32* %var3, align 4
  %18 = load i32, i32* %var3, align 4
  call void @f_printf(i32 signext %18)
  %19 = load i32, i32* %var0, align 4
  %20 = load i32, i32* %var5, align 4
  %sub13 = sub nsw i32 %19, %20
  store i32 %sub13, i32* %var1, align 4
  %21 = load i32, i32* %var1, align 4
  ret i32 %21
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @func4(i32 signext %p0, i32 signext %p1) #0 {
entry:
  %p0.addr = alloca i32, align 4
  %p1.addr = alloca i32, align 4
  %var0 = alloca i32, align 4
  %var1 = alloca i32, align 4
  %var2 = alloca i32, align 4
  %var3 = alloca i32, align 4
  %var4 = alloca i32, align 4
  %var5 = alloca i32, align 4
  %var6 = alloca i32, align 4
  store i32 %p0, i32* %p0.addr, align 4
  store i32 %p1, i32* %p1.addr, align 4
  %call = call i32 @f_scanf_nop()
  store i32 %call, i32* %var0, align 4
  %call1 = call i32 @f_rand()
  store i32 %call1, i32* %var1, align 4
  %call2 = call i32 @f_rand()
  store i32 %call2, i32* %var2, align 4
  %call3 = call i32 @f_rand()
  store i32 %call3, i32* %var3, align 4
  %call4 = call i32 @f_scanf_nop()
  store i32 %call4, i32* %var4, align 4
  store i32 696, i32* %var5, align 4
  store i32 -671, i32* %var6, align 4
  %0 = load i32, i32* %p1.addr, align 4
  %1 = load i32, i32* %var1, align 4
  %mul = mul nsw i32 %0, %1
  %2 = load i32, i32* %var6, align 4
  %mul5 = mul nsw i32 %mul, %2
  %3 = load i32, i32* %p1.addr, align 4
  %add = add nsw i32 %mul5, %3
  store i32 %add, i32* %var0, align 4
  %4 = load i32, i32* %var6, align 4
  %5 = load i32, i32* %var0, align 4
  %sub = sub nsw i32 %4, %5
  %6 = load i32, i32* %p1.addr, align 4
  %mul6 = mul nsw i32 %sub, %6
  store i32 %mul6, i32* %var4, align 4
  %7 = load i32, i32* %var0, align 4
  %8 = load i32, i32* %p1.addr, align 4
  %mul7 = mul nsw i32 %7, %8
  %9 = load i32, i32* %p0.addr, align 4
  %mul8 = mul nsw i32 %mul7, %9
  store i32 %mul8, i32* %p0.addr, align 4
  %10 = load i32, i32* %p1.addr, align 4
  %11 = load i32, i32* %var0, align 4
  %sub9 = sub nsw i32 %10, %11
  %12 = load i32, i32* %var6, align 4
  %add10 = add nsw i32 %sub9, %12
  store i32 %add10, i32* %var5, align 4
  %13 = load i32, i32* %var2, align 4
  %14 = load i32, i32* %var4, align 4
  %add11 = add nsw i32 %13, %14
  %15 = load i32, i32* %var1, align 4
  %sub12 = sub nsw i32 %add11, %15
  store i32 %sub12, i32* %var5, align 4
  %16 = load i32, i32* %var0, align 4
  %17 = load i32, i32* %var2, align 4
  %sub13 = sub nsw i32 %16, %17
  store i32 %sub13, i32* %var0, align 4
  %18 = load i32, i32* %var0, align 4
  ret i32 %18
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 {
entry:
  %retval = alloca i32, align 4
  %var0 = alloca i32, align 4
  %var1 = alloca i32, align 4
  %var2 = alloca i32, align 4
  %var3 = alloca i32, align 4
  store i32 0, i32* %retval, align 4
  %call = call i32 @f_rand()
  store i32 %call, i32* %var0, align 4
  %call1 = call i32 @f_scanf_nop()
  store i32 %call1, i32* %var1, align 4
  %call2 = call i32 @f_rand()
  store i32 %call2, i32* %var2, align 4
  %call3 = call i32 @f_rand()
  store i32 %call3, i32* %var3, align 4
  %0 = load i32, i32* %var0, align 4
  %call4 = call i32 @func0(i32 signext %0)
  %1 = load i32, i32* %var0, align 4
  %call5 = call i32 @func1(i32 signext %1)
  %call6 = call i32 @func2()
  %2 = load i32, i32* %var0, align 4
  %call7 = call i32 @func3(i32 signext %2)
  %3 = load i32, i32* %var0, align 4
  %4 = load i32, i32* %var1, align 4
  %call8 = call i32 @func4(i32 signext %3, i32 signext %4)
  ret i32 0
}

attributes #0 = { noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="mips32r2" "target-features"="+mips32r2,-noabicalls" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="mips32r2" "target-features"="+mips32r2,-noabicalls" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0 "}
