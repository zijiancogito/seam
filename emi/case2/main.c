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

int func0(int p0)
{
   int var0 = f_scanf_nop();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_rand();
   int var4 = f_scanf_nop();
   int var5 = 479;
   int var6 = -869;
   p0 = var5 + var0;
   f_printf(p0);
   var3 = var6 - var4;
   f_printf(var3);
   p0 = (var0 * var3) * var1;
   var2 = ((var5 + var2) + var1) * var5;
   f_printf(var2);
   var6 = p0 - var5;
   f_printf(var6);
   var1 = ((((((var3 + var6) * var0) * var2) * var4) + var5) * var0) * var6;
   return var1;
}

int func1(int p0, int p1)
{
   int var0 = f_rand();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_scanf_nop();
   int var4 = f_rand();
   int var5 = -548;
   int var6 = 421;
   var5 = var5 * var4;
   f_printf(var5);
   var0 = (p1 + var0) - var5;
   f_printf(var0);
   var3 = var4 - var0;
   var4 = var3 * p0;
   var4 = var5 + var1;
   var5 = var0 * var5;
   return var5;
}

int func2(int p0, int p1, int p2)
{
   int var0 = f_scanf_nop();
   int var1 = f_rand();
   int var2 = f_scanf_nop();
   int var3 = f_rand();
   int var4 = f_rand();
   int var5 = -969;
   int var6 = -128;
   var6 = p0 * var6;
   p0 = (((((p0 - var6) - var4) - var5) + p2) - var3) * p0;
   var1 = ((var6 - var4) * var6) - var5;
   f_printf(var1);
   p2 = ((((var3 - var0) * p2) - var2) * p1) - var2;
   f_printf(p2);
   p1 = p0 + var5;
   f_printf(p1);
   var0 = (p2 - var6) - var3;
   return var0;
}

int func3(int p0, int p1)
{
   int var0 = f_rand();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_scanf_nop();
   int var4 = f_scanf_nop();
   int var5 = -405;
   int var6 = -890;
   p0 = p0 + p1;
   f_printf(p0);
   var1 = var3 + p1;
   f_printf(var1);
   var6 = (var6 + var0) + var1;
   f_printf(var6);
   var0 = (p1 + p0) * var0;
   var0 = (var2 * p0) - p1;
   var2 = p0 + p1;
   return var2;
}

int func4(int p0, int p1, int p2)
{
   int var0 = f_scanf_nop();
   int var1 = f_scanf_nop();
   int var2 = f_scanf_nop();
   int var3 = f_scanf_nop();
   int var4 = f_rand();
   int var5 = 728;
   int var6 = 914;
   p1 = var2 - var6;
   var1 = var2 * var5;
   var4 = var1 + p2;
   var0 = var0 + var1;
   var5 = (p0 + var2) * var5;
   f_printf(var5);
   var0 = (var1 - var0) + var4;
   return var0;
}

int main(void)
{
   int var0 = f_scanf_nop();
   int var1 = f_scanf_nop();
   int var2 = f_scanf_nop();
   int var3 = f_rand();
   func0(var0);
   func1(var0, var1);
   func2(var0, var1, var2);
   func3(var0, var1);
   func4(var0, var1, var2);
   return 0;
}

