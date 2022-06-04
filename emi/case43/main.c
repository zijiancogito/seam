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

int func0(void)
{
   int var0 = f_scanf_nop();
   int var1 = f_scanf_nop();
   int var2 = f_scanf_nop();
   int var3 = f_scanf_nop();
   int var4 = f_scanf_nop();
   int var5 = 472;
   int var6 = 366;
   var2 = var3 * var1;
   var0 = (var2 + var0) - var4;
   var0 = var1 + var0;
   var4 = var5 - var1;
   var5 = var3 + var2;
   f_printf(var5);
   var0 = var2 - var3;
   return var0;
}

int func1(int p0, int p1)
{
   int var0 = f_rand();
   int var1 = f_rand();
   int var2 = f_scanf_nop();
   int var3 = f_scanf_nop();
   int var4 = f_rand();
   int var5 = -6;
   int var6 = 894;
   p0 = var4 + var6;
   var6 = ((var3 - var2) + var3) * var6;
   f_printf(var6);
   p1 = (var6 + var5) - var4;
   f_printf(p1);
   var1 = (((var1 + var3) * var4) + var1) - var4;
   f_printf(var1);
   var6 = (var5 + var1) + var2;
   var4 = var6 + var5;
   return var4;
}

int func2(int p0, int p1)
{
   int var0 = f_scanf_nop();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_rand();
   int var4 = f_rand();
   int var5 = 882;
   int var6 = 770;
   p0 = var5 + var3;
   f_printf(p0);
   var1 = (var6 - var0) * var1;
   f_printf(var1);
   var5 = var4 - var3;
   f_printf(var5);
   var5 = var5 + var2;
   var0 = p0 * var3;
   var0 = var6 - p1;
   return var0;
}

int func3(int p0, int p1, int p2)
{
   int var0 = f_rand();
   int var1 = f_rand();
   int var2 = f_rand();
   int var3 = f_rand();
   int var4 = f_scanf_nop();
   int var5 = 832;
   int var6 = 912;
   var5 = p0 + p1;
   f_printf(var5);
   var6 = var3 * var6;
   f_printf(var6);
   var1 = ((p1 + p2) - var3) * var4;
   f_printf(var1);
   var5 = ((((p2 + p0) - var6) * p1) - var3) + var0;
   f_printf(var5);
   var5 = p1 - p2;
   f_printf(var5);
   var5 = var2 - var3;
   return var5;
}

int func4(void)
{
   int var0 = f_rand();
   int var1 = f_rand();
   int var2 = f_scanf_nop();
   int var3 = f_scanf_nop();
   int var4 = f_scanf_nop();
   int var5 = 157;
   int var6 = 338;
   var1 = ((var4 + var1) - var6) - var2;
   var5 = (((var1 - var4) * var5) * var0) - var5;
   f_printf(var5);
   var4 = var5 - var1;
   f_printf(var4);
   var2 = var3 * var6;
   var0 = var0 + var6;
   var1 = var1 - var0;
   return var1;
}

int main(void)
{
   int var0 = f_scanf_nop();
   int var1 = f_scanf_nop();
   int var2 = f_rand();
   int var3 = f_scanf_nop();
   func0();
   func1(var0, var1);
   func2(var0, var1);
   func3(var0, var1, var2);
   func4();
   return 0;
}

