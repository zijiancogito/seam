  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
  Entries:
BIN: case1-x64.ir
  FUNCTION: 0f4e41ff-d755-4e72-baf3-6ad1c1ff50be
    BLOCK: 0x10c0
      0x10c0: endbr64 
      0x10c4: bnd jmp qword ptr [rip + 0x2efd]
  FUNCTION: 1d4304fb-a339-44d7-b40e-0da4050cdd22
    BLOCK: 0x1020
      0x1020: push qword ptr [rip + 0x2f7a]
      0x1026: bnd jmp qword ptr [rip + 0x2f7b]
    BLOCK: 0x1030
      0x1030: endbr64 
      0x1034: push 0
      0x1039: bnd jmp 0x1020
    BLOCK: 0x1040
      0x1040: endbr64 
      0x1044: push 1
      0x1049: bnd jmp 0x1020
    BLOCK: 0x1050
      0x1050: endbr64 
      0x1054: push 2
      0x1059: bnd jmp 0x1020
    BLOCK: 0x1060
      0x1060: endbr64 
      0x1064: push 3
      0x1069: bnd jmp 0x1020
    BLOCK: 0x1070
      0x1070: endbr64 
      0x1074: push 4
      0x1079: bnd jmp 0x1020
  FUNCTION: 1d6e10de-4289-4fd9-9af6-76d9dd34844e
    BLOCK: 0x1080
      0x1080: endbr64 
      0x1084: bnd jmp qword ptr [rip + 0x2f6d]
  FUNCTION: 31d3e7e2-bab5-4784-975b-9b1035f97f19
    BLOCK: 0x11c9
      0x11c9: endbr64 
      0x11cd: push rbp
      0x11ce: mov rbp, rsp
      0x11d1: sub rsp, 0x70
      0x11d5: mov rax, qword ptr fs:[0x28]
      0x11de: mov qword ptr [rbp - 8], rax
      0x11e2: xor eax, eax
      0x11e4: mov dword ptr [rbp - 0x58], 0
      0x11eb: lea rax, [rbp - 0x40]
      0x11ef: mov rdi, rax
      0x11f2: mov eax, 0
      0x11f7: call 0x10d0
    BLOCK: 0x11fc
      0x11fc: lea rax, [rbp - 0x4a]
      0x1200: mov rdi, rax
      0x1203: mov eax, 0
      0x1208: call 0x10d0
    BLOCK: 0x120d
      0x120d: lea rax, [rbp - 0x40]
      0x1211: mov rdi, rax
      0x1214: call 0x1090
    BLOCK: 0x1219
      0x1219: mov dword ptr [rbp - 0x54], eax
      0x121c: lea rax, [rbp - 0x4a]
      0x1220: mov rdi, rax
      0x1223: call 0x1090
    BLOCK: 0x1228
      0x1228: mov dword ptr [rbp - 0x50], eax
      0x122b: mov dword ptr [rbp - 0x64], 0
      0x1232: jmp 0x127b
    BLOCK: 0x1234
      0x1234: mov dword ptr [rbp - 0x60], 0
      0x123b: mov eax, dword ptr [rbp - 0x64]
      0x123e: mov dword ptr [rbp - 0x5c], eax
      0x1241: jmp 0x124b
    BLOCK: 0x1243
      0x1243: add dword ptr [rbp - 0x60], 1
      0x1247: add dword ptr [rbp - 0x5c], 1
    BLOCK: 0x124b
      0x124b: mov eax, dword ptr [rbp - 0x60]
      0x124e: cmp eax, dword ptr [rbp - 0x50]
      0x1251: jge 0x126b
    BLOCK: 0x1253
      0x1253: mov eax, dword ptr [rbp - 0x60]
      0x1256: cdqe 
      0x1258: movzx edx, byte ptr [rbp + rax - 0x4a]
      0x125d: mov eax, dword ptr [rbp - 0x5c]
      0x1260: cdqe 
      0x1262: movzx eax, byte ptr [rbp + rax - 0x40]
      0x1267: cmp dl, al
      0x1269: je 0x1243
    BLOCK: 0x126b
      0x126b: mov eax, dword ptr [rbp - 0x60]
      0x126e: cmp eax, dword ptr [rbp - 0x50]
      0x1271: jne 0x1277
    BLOCK: 0x1273
      0x1273: add dword ptr [rbp - 0x58], 1
    BLOCK: 0x1277
      0x1277: add dword ptr [rbp - 0x64], 1
    BLOCK: 0x127b
      0x127b: mov eax, dword ptr [rbp - 0x54]
      0x127e: sub eax, dword ptr [rbp - 0x50]
      0x1281: cmp dword ptr [rbp - 0x64], eax
      0x1284: jle 0x1234
    BLOCK: 0x1286
      0x1286: mov eax, dword ptr [rbp - 0x58]
      0x1289: mov esi, eax
      0x128b: lea rdi, [rip + 0xd72]
      0x1292: mov eax, 0
      0x1297: call 0x10c0
    BLOCK: 0x129c
      0x129c: lea rdi, [rip + 0xd65]
      0x12a3: call 0x10b0
    BLOCK: 0x12a8
      0x12a8: mov eax, 0
      0x12ad: mov rcx, qword ptr [rbp - 8]
      0x12b1: xor rcx, qword ptr fs:[0x28]
      0x12ba: je 0x12c1
    BLOCK: 0x12bc
      0x12bc: call 0x10a0
    BLOCK: 0x12c1
      0x12c1: leave 
      0x12c2: ret 
    BLOCK: 0x12c3
      0x12c3: nop word ptr cs:[rax + rax]
      0x12cd: nop dword ptr [rax]
  FUNCTION: 372b796f-97cd-4f15-84b3-19e7363499be
    BLOCK: 0x10e0
      0x10e0: endbr64 
      0x10e4: xor ebp, ebp
      0x10e6: mov r9, rdx
      0x10e9: pop rsi
      0x10ea: mov rdx, rsp
      0x10ed: and rsp, 0xfffffffffffffff0
      0x10f1: push rax
      0x10f2: push rsp
      0x10f3: lea r8, [rip + 0x246]
      0x10fa: lea rcx, [rip + 0x1cf]
      0x1101: lea rdi, [rip + 0xc1]
      0x1108: call qword ptr [rip + 0x2ed2]
    BLOCK: 0x110e
      0x110e: hlt 
    BLOCK: 0x110f
      0x110f: nop 
  FUNCTION: 5458e2fc-56c5-44c8-806c-eb8bd4fec7c8
    BLOCK: 0x1110
      0x1110: lea rdi, [rip + 0x2ef9]
      0x1117: lea rax, [rip + 0x2ef2]
      0x111e: cmp rax, rdi
      0x1121: je 0x1138
    BLOCK: 0x1123
      0x1123: mov rax, qword ptr [rip + 0x2eae]
      0x112a: test rax, rax
      0x112d: je 0x1138
    BLOCK: 0x112f
      0x112f: jmp rax
    BLOCK: 0x1138
      0x1138: ret 
  FUNCTION: 5bb69a8e-e555-41f5-8b39-ed1c3ecaa9f2
    BLOCK: 0x1340
      0x1340: endbr64 
      0x1344: ret 
  FUNCTION: 7388bc45-5b5e-4a8f-90dd-7bef6df2e0a8
    BLOCK: 0x12d0
      0x12d0: endbr64 
      0x12d4: push r15
      0x12d6: lea r15, [rip + 0x2abb]
      0x12dd: push r14
      0x12df: mov r14, rdx
      0x12e2: push r13
      0x12e4: mov r13, rsi
      0x12e7: push r12
      0x12e9: mov r12d, edi
      0x12ec: push rbp
      0x12ed: lea rbp, [rip + 0x2aac]
      0x12f4: push rbx
      0x12f5: sub rbp, r15
      0x12f8: sub rsp, 8
      0x12fc: call 0x1000
    BLOCK: 0x1301
      0x1301: sar rbp, 3
      0x1305: je 0x1326
    BLOCK: 0x1307
      0x1307: xor ebx, ebx
      0x1309: nop dword ptr [rax]
    BLOCK: 0x1310
      0x1310: mov rdx, r14
      0x1313: mov rsi, r13
      0x1316: mov edi, r12d
      0x1319: call qword ptr [r15 + rbx*8]
    BLOCK: 0x131d
      0x131d: add rbx, 1
      0x1321: cmp rbp, rbx
      0x1324: jne 0x1310
    BLOCK: 0x1326
      0x1326: add rsp, 8
      0x132a: pop rbx
      0x132b: pop rbp
      0x132c: pop r12
      0x132e: pop r13
      0x1330: pop r14
      0x1332: pop r15
      0x1334: ret 
    BLOCK: 0x1335
      0x1335: nop word ptr cs:[rax + rax]
  FUNCTION: 866885f7-614d-409d-b12a-f439bc5d3170
    BLOCK: 0x1140
      0x1140: lea rdi, [rip + 0x2ec9]
      0x1147: lea rsi, [rip + 0x2ec2]
      0x114e: sub rsi, rdi
      0x1151: mov rax, rsi
      0x1154: shr rsi, 0x3f
      0x1158: sar rax, 3
      0x115c: add rsi, rax
      0x115f: sar rsi, 1
      0x1162: je 0x1178
    BLOCK: 0x1164
      0x1164: mov rax, qword ptr [rip + 0x2e85]
      0x116b: test rax, rax
      0x116e: je 0x1178
    BLOCK: 0x1170
      0x1170: jmp rax
    BLOCK: 0x1178
      0x1178: ret 
  FUNCTION: 97445a2f-fd59-4cd6-806d-13a2652efc60
    BLOCK: 0x11c0
      0x11c0: endbr64 
      0x11c4: jmp 0x1140
  FUNCTION: 9faca5b8-b15b-4495-ab49-e0b957cf8593
    BLOCK: 0x10b0
      0x10b0: endbr64 
      0x10b4: bnd jmp qword ptr [rip + 0x2f05]
  FUNCTION: aed195ac-aff4-42fb-9869-8dc46eeed9ff
    BLOCK: 0x1090
      0x1090: endbr64 
      0x1094: bnd jmp qword ptr [rip + 0x2f15]
  FUNCTION: bad4c956-afab-40be-ad09-3f84e9435716
    BLOCK: 0x1180
      0x1180: endbr64 
      0x1184: cmp byte ptr [rip + 0x2e85], 0
      0x118b: jne 0x11b8
    BLOCK: 0x118d
      0x118d: push rbp
      0x118e: cmp qword ptr [rip + 0x2e62], 0
      0x1196: mov rbp, rsp
      0x1199: je 0x11a7
    BLOCK: 0x119b
      0x119b: mov rdi, qword ptr [rip + 0x2e66]
      0x11a2: call 0x1080
    BLOCK: 0x11a7
      0x11a7: call 0x1110
    BLOCK: 0x11ac
      0x11ac: mov byte ptr [rip + 0x2e5d], 1
      0x11b3: pop rbp
      0x11b4: ret 
    BLOCK: 0x11b8
      0x11b8: ret 
  FUNCTION: cf0fee6a-f4e0-4ee2-8f50-3de5a622dd41
    BLOCK: 0x10d0
      0x10d0: endbr64 
      0x10d4: bnd jmp qword ptr [rip + 0x2ef5]
  FUNCTION: db331560-6aeb-47d6-9898-99ad05c69c25
    BLOCK: 0x1348
      0x1348: endbr64 
      0x134c: sub rsp, 8
      0x1350: add rsp, 8
      0x1354: ret 
  FUNCTION: e34d4bc6-eef1-46ef-9209-547fcf5b02fd
    BLOCK: 0x10a0
      0x10a0: endbr64 
      0x10a4: bnd jmp qword ptr [rip + 0x2f0d]
  FUNCTION: e3c39700-5cab-4e42-a471-b42c6d6adbe7
    BLOCK: 0x1000
      0x1000: endbr64 
      0x1004: sub rsp, 8
      0x1008: mov rax, qword ptr [rip + 0x2fd9]
      0x100f: test rax, rax
      0x1012: je 0x1016
    BLOCK: 0x1014
      0x1014: call rax
    BLOCK: 0x1016
      0x1016: add rsp, 8
      0x101a: ret 
