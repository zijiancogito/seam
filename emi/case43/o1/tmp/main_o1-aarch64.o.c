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
int64_t func3(void);
int64_t func4(void);

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

// Address range: 0x44 - 0x88
int64_t func0(void) {
    // 0x44
    f_scanf_nop();
    int64_t v1 = f_scanf_nop(); // 0x54
    f_scanf_nop();
    int64_t v2 = f_scanf_nop(); // 0x60
    f_scanf_nop();
    f_printf();
    return v2 * v1 - v2 & 0xffffffff;
}

// Address range: 0x88 - 0x114
int64_t func1(void) {
    // 0x88
    int64_t v1; // 0x88
    int64_t v2 = rand(rand(v1)); // 0xa0
    int64_t v3 = f_scanf_nop(); // 0xa8
    int64_t v4 = f_scanf_nop(); // 0xb0
    int64_t v5 = rand(v4); // 0xb8
    f_printf();
    f_printf();
    f_printf();
    return v2 + 0xfffffff4 + v3 - v5 + (v4 + v2) * v5 & 0xffffffff;
}

// Address range: 0x114 - 0x188
int64_t func2(void) {
    // 0x114
    f_scanf_nop();
    rand(rand(rand(f_scanf_nop())));
    f_printf();
    f_printf();
    f_printf();
    int64_t v1; // 0x114
    return 770 - v1 & 0xffffffff;
}

// Address range: 0x188 - 0x230
int64_t func3(void) {
    // 0x188
    int64_t v1; // 0x188
    int64_t v2 = rand(rand(rand(v1))); // 0x1b8
    int64_t v3 = rand(v2); // 0x1c0
    f_scanf_nop();
    f_printf();
    f_printf();
    f_printf();
    f_printf();
    f_printf();
    return v2 - v3 & 0xffffffff;
}

// Address range: 0x230 - 0x2a4
int64_t func4(void) {
    // 0x230
    int64_t v1; // 0x230
    int64_t v2 = rand(v1); // 0x240
    int64_t v3 = rand(v2); // 0x248
    int64_t v4 = f_scanf_nop(); // 0x250
    f_scanf_nop();
    int64_t v5 = f_scanf_nop(); // 0x25c
    f_printf();
    f_printf();
    return 0xfffffd5c - v2 + v3 - v4 + v5 & 0xffffffff;
}

// Address range: 0x2a4 - 0x308
int main(int argc, char ** argv) {
    // 0x2a4
    f_scanf_nop();
    rand(f_scanf_nop());
    f_scanf_nop();
    func0();
    func1();
    func2();
    func3();
    func4();
    return 0;
}

// Address range: 0x308 - 0x309
int64_t _24_d_1(void) {
    // 0x308
    int64_t result; // 0x308
    return result;
}

// --------------- Dynamically Linked Functions ---------------

// int64_t rand(int64_t a1);

// --------------------- Meta-Information ---------------------

// Detected functions: 9

