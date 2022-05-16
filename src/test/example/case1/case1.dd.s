#===================================
.intel_syntax noprefix
#===================================

nop
nop
nop
nop
nop
nop
nop
nop

#===================================
.section .interp ,"a",@progbits
#===================================

.align 1
          .string "/lib64/ld-linux-x86-64.so.2"
#===================================
# end section .interp
#===================================

#===================================
.text
#===================================

          .byte 0xf
          .byte 0x1f
          .byte 0x80
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0xf
          .byte 0x1f
          .byte 0x80
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x66
          .byte 0xf
          .byte 0x1f
          .byte 0x44
          .byte 0x0
          .byte 0x0
          .byte 0xf
          .byte 0x1f
          .byte 0x80
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0xf
          .byte 0x1f
          .byte 0x0
          .byte 0xf
          .byte 0x1f
          .byte 0x80
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
#-----------------------------------
.globl main
.type main, @function
#-----------------------------------
main:

.cfi_startproc 
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 7, 8
.cfi_offset 16, -8
            nop
            nop
            nop
            nop
            push RBP
.cfi_def_cfa_offset 16
.cfi_offset 6, -16
            mov RBP,RSP
.cfi_def_cfa_register 6
            sub RSP,112
            mov RAX,QWORD PTR FS:[40]
            mov QWORD PTR [RBP-8],RAX
            xor EAX,EAX
            mov DWORD PTR [RBP-88],0
            lea RAX,QWORD PTR [RBP-64]
            mov RDI,RAX
            mov EAX,0
            call gets@PLT

            lea RAX,QWORD PTR [RBP-74]
            mov RDI,RAX
            mov EAX,0
            call gets@PLT

            lea RAX,QWORD PTR [RBP-64]
            mov RDI,RAX
            call strlen@PLT

            mov DWORD PTR [RBP-84],EAX
            lea RAX,QWORD PTR [RBP-74]
            mov RDI,RAX
            call strlen@PLT

            mov DWORD PTR [RBP-80],EAX
            mov DWORD PTR [RBP-100],0
            jmp .L_127b
.L_1234:

            mov DWORD PTR [RBP-96],0
            mov EAX,DWORD PTR [RBP-100]
            mov DWORD PTR [RBP-92],EAX
            jmp .L_124b
.L_1243:

            add DWORD PTR [RBP-96],1
            add DWORD PTR [RBP-92],1
.L_124b:

            mov EAX,DWORD PTR [RBP-96]
            cmp EAX,DWORD PTR [RBP-80]
            jge .L_126b

            mov EAX,DWORD PTR [RBP-96]
            cdqe 
            movzx EDX,BYTE PTR [RBP+RAX*1-74]
            mov EAX,DWORD PTR [RBP-92]
            cdqe 
            movzx EAX,BYTE PTR [RBP+RAX*1-64]
            cmp DL,AL
            je .L_1243
.L_126b:

            mov EAX,DWORD PTR [RBP-96]
            cmp EAX,DWORD PTR [RBP-80]
            jne .L_1277

            add DWORD PTR [RBP-88],1
.L_1277:

            add DWORD PTR [RBP-100],1
.L_127b:

            mov EAX,DWORD PTR [RBP-84]
            sub EAX,DWORD PTR [RBP-80]
            cmp DWORD PTR [RBP-100],EAX
            jle .L_1234

            mov EAX,DWORD PTR [RBP-88]
            mov ESI,EAX
            lea RDI,QWORD PTR [RIP+.L_2004]
            mov EAX,0
            call printf@PLT

            lea RDI,QWORD PTR [RIP+.L_2008]
            call system@PLT

            mov EAX,0
            mov RCX,QWORD PTR [RBP-8]
            xor RCX,QWORD PTR FS:[40]
            je .L_12c1

            call __stack_chk_fail@PLT
.L_12c1:

            leave 
.cfi_def_cfa 7, 8
            ret 
.cfi_endproc 

            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
#===================================
# end section .text
#===================================

#===================================
.section .rodata ,"a",@progbits
#===================================

.align 4
          .byte 0x1
          .byte 0x0
          .byte 0x2
          .byte 0x0
.L_2004:
          .string "%d\n"
.L_2008:
          .string "pause"
#===================================
# end section .rodata
#===================================

#===================================
.section .init_array ,"wa"
#===================================

.align 8
__frame_dummy_init_array_entry:
__init_array_start:
#===================================
# end section .init_array
#===================================

#===================================
.section .fini_array ,"wa"
#===================================

.align 8
__do_global_dtors_aux_fini_array_entry:
__init_array_end:
#===================================
# end section .fini_array
#===================================

#===================================
.data
#===================================

.align 8
#-----------------------------------
.weak data_start
.type data_start, @notype
#-----------------------------------
data_start:
          .zero 8
          .quad 0
#           : WARNING:0: no symbol for address 0x4008 
#===================================
# end section .data
#===================================

#===================================
.bss
#===================================

.align 1
completed.8060:
#-----------------------------------
.globl _edata
.type _edata, @notype
#-----------------------------------
_edata:
          .zero 8
#-----------------------------------
.globl _end
.type _end, @notype
#-----------------------------------
_end:
#===================================
# end section .bss
#===================================
#-----------------------------------
.weak __gmon_start__
.type __gmon_start__, @notype
#-----------------------------------
#-----------------------------------
.weak _ITM_registerTMCloneTable
.type _ITM_registerTMCloneTable, @notype
#-----------------------------------
#-----------------------------------
.weak _ITM_deregisterTMCloneTable
.type _ITM_deregisterTMCloneTable, @notype
#-----------------------------------
#-----------------------------------
.weak __cxa_finalize
.type __cxa_finalize, @function
#-----------------------------------
#-----------------------------------
.globl system
.type system, @function
#-----------------------------------
#-----------------------------------
.globl strlen
.type strlen, @function
#-----------------------------------
#-----------------------------------
.globl printf
.type printf, @function
#-----------------------------------
#-----------------------------------
.globl gets
.type gets, @function
#-----------------------------------
#-----------------------------------
.globl __stack_chk_fail
.type __stack_chk_fail, @function
#-----------------------------------
#-----------------------------------
.globl __libc_start_main
.type __libc_start_main, @function
#-----------------------------------
