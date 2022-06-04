#include <stdio.h>

void f_printf(int p0)
{
   printf("%d", p0);
}

int f_scanf_nop(void)
{
   int var0;
   scanf("%d", &var0);
   return var0;
}

int f_rand(void)
{
   int var0 = rand();
   return var0;
}

int func0(int p0, int p1)
{
   int var0 = f_rand();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_rand();
   int var4 = f_rand();
   int var5 = -20;
   int var6 = -701;
   var5 = var4 * var0;
   f_printf(var5);
   var6 = ((((var0 + p0) + var4) * var1) + p0) - var1;
   var1 = p0 - var1;
   f_printf(var1);
   var3 = var2 - var1;
   var5 = var4 - var2;
   f_printf(var5);
   var0 = var2 * var6;
   return var0;
}

int func1(int p0)
{
   int var0 = f_scanf_nop();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_rand();
   int var4 = f_rand();
   int var5 = -406;
   int var6 = -825;
   var3 = var0 * var2;
   var5 = var1 + var3;
   f_printf(var5);
   var2 = (var2 + var4) + var1;
   f_printf(var2);
   var6 = ((var0 * var5) * var4) * var2;
   var1 = (((((var0 - var1) + var5) - var3) + p0) + var5) * p0;
   f_printf(var1);
   var3 = (((((var2 * var3) * var4) - var6) * var3) + var1) - var5;
   return var3;
}

int func2(int p0, int p1)
{
   int var0 = f_scanf_nop();
   int var1 = f_rand();
   int var2 = f_rand();
   int var3 = f_rand();
   int var4 = f_rand();
   int var5 = 508;
   int var6 = -583;
   var0 = var5 + var2;
   f_printf(var0);
   var3 = (p0 - var2) - var3;
   var5 = ((p1 - var6) * var0) * p0;
   var4 = var0 + var5;
   var2 = var4 + var5;
   var2 = (var5 * var4) + var3;
   return var2;
}

int func3(void)
{
   int var0 = f_scanf_nop();
   int var1 = f_rand();
   int var2 = f_scanf_nop();
   int var3 = f_rand();
   int var4 = f_rand();
   int var5 = 638;
   int var6 = 498;
   var5 = var0 * var6;
   var6 = var0 + var6;
   var6 = var6 - var0;
   var3 = (var3 - var4) - var0;
   var1 = var1 * var6;
   var0 = var6 - var4;
   return var0;
}

int func4(int p0)
{
   int var0 = f_scanf_nop();
   int var1 = f_scanf_nop();
   int var2 = f_scanf_nop();
   int var3 = f_scanf_nop();
   int var4 = f_rand();
   int var5 = -604;
   int var6 = 13;
   var3 = var5 - var0;
   f_printf(var3);
   p0 = (var5 + var6) - var0;
   var3 = p0 - var6;
   f_printf(var3);
   p0 = (var5 * var1) * var6;
   var2 = (var2 - var6) * var3;
   p0 = p0 - var1;
   return p0;
}

int main(void)
{
   int var0 = f_scanf_nop();
   int var1 = f_rand();
   int var2 = f_scanf_nop();
   int var3 = f_rand();
   func0(var0, var1);
   func1(var0);
   func2(var0, var1);
   func3();
   func4(var0);
   return 0;
}

