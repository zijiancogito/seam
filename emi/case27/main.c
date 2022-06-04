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
   int var0 = f_rand();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_rand();
   int var4 = f_rand();
   int var5 = -342;
   int var6 = -240;
   var2 = (((((var6 - p0) + var1) - p0) * var6) * p0) - var5;
   f_printf(var2);
   var4 = var6 * var4;
   f_printf(var4);
   var1 = ((var4 + var0) - p0) - var3;
   f_printf(var1);
   p0 = var1 + var4;
   var0 = var4 * p0;
   f_printf(var0);
   var4 = (p0 + var3) + p0;
   return var4;
}

int func1(int p0)
{
   int var0 = f_scanf_nop();
   int var1 = f_rand();
   int var2 = f_scanf_nop();
   int var3 = f_scanf_nop();
   int var4 = f_rand();
   int var5 = -893;
   int var6 = -525;
   var6 = p0 + var0;
   f_printf(var6);
   var0 = (p0 - var3) + var2;
   var0 = ((p0 - var0) + var6) * var1;
   var5 = var3 * p0;
   var4 = (var0 - var3) + var1;
   var4 = var5 - var0;
   return var4;
}

int func2(void)
{
   int var0 = f_scanf_nop();
   int var1 = f_rand();
   int var2 = f_scanf_nop();
   int var3 = f_scanf_nop();
   int var4 = f_rand();
   int var5 = 759;
   int var6 = -296;
   var0 = var4 * var6;
   var1 = var6 - var4;
   var6 = var1 * var0;
   var1 = ((var1 - var2) * var4) * var3;
   var6 = (((var3 - var1) + var5) + var1) + var0;
   f_printf(var6);
   var0 = ((((var3 - var2) - var5) - var0) * var6) * var0;
   return var0;
}

int func3(int p0)
{
   int var0 = f_scanf_nop();
   int var1 = f_rand();
   int var2 = f_scanf_nop();
   int var3 = f_scanf_nop();
   int var4 = f_scanf_nop();
   int var5 = 633;
   int var6 = 485;
   var1 = p0 + var2;
   var0 = p0 - var6;
   var2 = (var0 * var1) - var4;
   f_printf(var2);
   var4 = (((((var0 + var5) - var4) - var1) - var3) * p0) - var6;
   f_printf(var4);
   var3 = var5 - p0;
   f_printf(var3);
   var1 = var0 - var5;
   return var1;
}

int func4(int p0, int p1)
{
   int var0 = f_scanf_nop();
   int var1 = f_rand();
   int var2 = f_rand();
   int var3 = f_rand();
   int var4 = f_scanf_nop();
   int var5 = 696;
   int var6 = -671;
   var0 = ((p1 * var1) * var6) + p1;
   var4 = (var6 - var0) * p1;
   p0 = (var0 * p1) * p0;
   var5 = (p1 - var0) + var6;
   var5 = (var2 + var4) - var1;
   var0 = var0 - var2;
   return var0;
}

int main(void)
{
   int var0 = f_rand();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_rand();
   func0(var0);
   func1(var0);
   func2();
   func3(var0);
   func4(var0, var1);
   return 0;
}

