//
// This file was generated by the Retargetable Decompiler
// Website: https://retdec.com
//

#include <stdint.h>
#include <stdlib.h>

// ------------------- Function Prototypes --------------------

int64_t _24_d_1(void);
int64_t f_printf(void);
int64_t f_scanf_nop(void);
int64_t func0(void);
int64_t func1(void);
int64_t func2(void);
int64_t func3(int64_t a1);
int64_t func4(void);

// --------------------- Global Variables ---------------------

int32_t g1;

// ------------------------ Functions -------------------------

// Address range: 0x0 - 0x10
int64_t f_printf(void) {
    // 0x0
    int64_t v1; // 0x0
    return v1 + (int64_t)"%d";
}

// Address range: 0x14 - 0x2c
int64_t f_scanf_nop(void) {
    // 0x14
    return (int64_t)"%d";
}

// Address range: 0x44 - 0xbc
int64_t func0(void) {
    // 0x44
    int64_t v1; // 0x44
    int64_t v2 = v1;
    int64_t v3 = rand(v2); // 0x5c
    int64_t v4 = f_scanf_nop(); // 0x64
    int64_t v5 = rand(v4); // 0x6c
    int64_t v6 = rand(rand(v5)); // 0x78
    f_printf();
    f_printf();
    f_printf();
    return (v2 - v4 + (v3 + v2 + v6) * v4) * v5 & 0xffffffff;
}

// Address range: 0xbc - 0x164
int64_t func1(void) {
    // 0xbc
    int64_t v1; // 0xbc
    int64_t v2 = v1;
    int64_t v3 = f_scanf_nop(); // 0xd8
    int64_t v4 = f_scanf_nop(); // 0xe0
    int64_t v5 = rand(v4); // 0xe8
    int64_t v6 = rand(rand(v5)); // 0xf4
    int64_t v7 = v5 * v3; // 0xf8
    int64_t v8 = v7 + v4; // 0xfc
    f_printf();
    f_printf();
    f_printf();
    return (v3 + v2 + v8) * v2 - v8 + v6 * v7 * (v5 + v4 + v6) * (v7 - v8 * v3) & 0xffffffff;
}

// Address range: 0x164 - 0x1d8
int64_t func2(void) {
    int64_t v1 = rand(rand(f_scanf_nop())); // 0x188
    int64_t v2 = rand(v1); // 0x190
    rand(v2);
    int64_t v3 = v1 + 508; // 0x19c
    f_printf();
    int64_t v4; // 0x164
    int64_t v5 = (v4 + 583) * v4 * v3; // 0x1c4
    return v4 - v1 - v2 + (v5 + v3) * v5 & 0xffffffff;
}

// Address range: 0x1d8 - 0x204
int64_t func3(int64_t a1) {
    // 0x1d8
    rand(f_scanf_nop());
    return 498 - rand(rand(f_scanf_nop())) & 0xffffffff;
}

// Address range: 0x204 - 0x258
int64_t func4(void) {
    // 0x204
    f_scanf_nop();
    int64_t v1 = f_scanf_nop(); // 0x218
    f_scanf_nop();
    rand(f_scanf_nop());
    f_printf();
    f_printf();
    return 0xffffe153 * v1 & 0xffffffff;
}

// Address range: 0x258 - 0x2b0
int main(int argc, char ** argv) {
    // 0x258
    rand(f_scanf_nop());
    rand(f_scanf_nop());
    func0();
    func1();
    func2();
    func3((int64_t)&g1);
    func4();
    return 0;
}

// Address range: 0x2b0 - 0x2b1
int64_t _24_d_1(void) {
    // 0x2b0
    int64_t result; // 0x2b0
    return result;
}

// --------------- Dynamically Linked Functions ---------------

// int64_t rand(int64_t a1);

// --------------------- Meta-Information ---------------------

// Detected functions: 9
