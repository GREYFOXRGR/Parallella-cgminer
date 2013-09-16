.section .text

.global _salsa20_8

_salsa20_8:

ldr r16,[r0,+0x0]
ldr r17,[r1,+0x0]

ldr r18,[r0,+0x1]
ldr r19,[r1,+0x1]

ldr r20,[r0,+0x2]
ldr r21,[r1,+0x2]

ldr r22,[r0,+0x3]
ldr r23,[r1,+0x3]

ldr r24,[r0,+0x4]
ldr r25,[r1,+0x4]

ldr r26,[r0,+0x5]
ldr r27,[r1,+0x5]

eor r44,r16,r17
eor r45,r18,r19
eor r46,r20,r21
eor r47,r22,r23
eor r48,r24,r25
eor r49,r26,r27

ldr r16,[r0,+0x6]
ldr r17,[r1,+0x6]

ldr r18,[r0,+0x7]
ldr r19,[r1,+0x7]

ldr r20,[r0,+0x8]
ldr r21,[r1,+0x8]

ldr r22,[r0,+0x9]
ldr r23,[r1,+0x9]

ldr r24,[r0,+0xa]
ldr r25,[r1,+0xa]

ldr r26,[r0,+0xb]
ldr r27,[r1,+0xb]

eor r50,r16,r17
eor r51,r18,r19
eor r52,r20,r21
eor r53,r22,r23
eor r54,r24,r25
eor r55,r26,r27

ldr r16,[r0,+0xc]
ldr r17,[r1,+0xc]

ldr r18,[r0,+0xd]
ldr r19,[r1,+0xd]

ldr r20,[r0,+0xe]
ldr r21,[r1,+0xe]

ldr r22,[r0,+0xf]
ldr r23,[r1,+0xf]

str r44,[r2,+0x0]
str r48,[r2,+0x4]

eor r56,r16,r17
str r56,[r2,+0xc]

eor r59,r22,r23
str r59,[r2,+0xf]
str r47,[r2,+0x3]

str r45,[r2,+0x1]
str r49,[r2,+0x5]
str r53,[r2,+0x9]

str r50,[r2,+0x6]
str r54,[r2,+0xa]
str r55,[r2,+0xb]

eor r57,r18,r19
eor r58,r20,r21
str r57,[r2,+0xd]
str r58,[r2,+0xe]

str r46,[r2,+0x2]
str r51,[r2,+0x7]
str r52,[r2,+0x8]


; The multiplication constants must be in CPU Registers
mov r16,0x80     ; 2^7
mov r17,0x200    ; 2^9
mov r18,0x2000   ; 2^13
eor r19,r19,r19
movt r19,0x4  ; 2^18

mov r3,0x8
FOR:

BL _R19
BL _R17
BL _R13
BL _R0e

BL _EXHANGE

sub r3,r3,1
bne FOR

ldr r0,[r2,+0x0]
ldr r1,[r2,+0x1]
ldr r3,[r2,+0x2]
ldr r12,[r2,+0x3]
ldr r16,[r2,+0x4]
ldr r17,[r2,+0x5]
ldr r18,[r2,+0x6]
ldr r19,[r2,+0x7]
ldr r20,[r2,+0x8]
ldr r21,[r2,+0x9]
ldr r22,[r2,+0xa]
ldr r23,[r2,+0xb]
ldr r24,[r2,+0xc]
ldr r25,[r2,+0xd]
ldr r26,[r2,+0xe]
ldr r27,[r2,+0xf]

add r0,r0,r44
add r1,r1,r45
add r3,r3,r46
add r12,r12,r47
add r16,r16,r48
add r17,r17,r49
add r18,r18,r50
add r19,r19,r51
add r20,r20,r52
add r21,r21,r53
add r22,r22,r54
add r23,r23,r55
add r24,r24,r56
add r25,r25,r57
add r26,r26,r58
add r27,r27,r59

str r0,[r2,+0x0]
str r1,[r2,+0x1]
str r3,[r2,+0x2]
str r12,[r2,+0x3]
str r16,[r2,+0x4]
str r17,[r2,+0x5]
str r18,[r2,+0x6]
str r19,[r2,+0x7]
str r20,[r2,+0x8]
str r21,[r2,+0x9]
str r22,[r2,+0xa]
str r23,[r2,+0xb]
str r24,[r2,+0xc]
str r25,[r2,+0xd]
str r26,[r2,+0xe]
str r27,[r2,+0xf]

rts

_R19:
;Macro R
add r20,r44,r56
lsr r21,r20,0x19
imadd r21,r20,r16

;Macro R
add r22,r49,r45
lsr r23,r22,0x19
imadd r23,r22,r16

;Macro R
add r24,r54,r50
lsr r25,r24,0x19
imadd r25,r22,r16

;Macro R
add r26,r59,r55
lsr r27,r26,0x19
imadd r27,r26,r16

eor r48,r48,r21
eor r53,r53,r23
eor r55,r55,r25
eor r47,r47,r27
rts

_R17:
;Macro R
add r20,r48,r56
lsr r21,r20,0x19
imadd r21,r20,r17

;Macro R
add r22,r53,r49
lsr r23,r22,0x19
imadd r23,r22,r17

;Macro R
add r24,r58,r54
lsr r25,r24,0x19
imadd r25,r22,r17

;Macro R
add r26,r47,r59
lsr r27,r26,0x19
imadd r27,r26,r17

eor r52,r52,r21
eor r57,r57,r23
eor r46,r46,r25
eor r51,r51,r27
rts

_R13:
;Macro R
add r20,r52,r48
lsr r21,r20,0x19
imadd r21,r20,r18

;Macro R
add r22,r57,r53
lsr r23,r22,0x19
imadd r23,r22,r18

;Macro R
add r24,r46,r58
lsr r25,r24,0x19
imadd r25,r22,r18

;Macro R
add r26,r51,r47
lsr r27,r26,0x19
imadd r27,r26,r18

eor r46,r46,r21
eor r45,r45,r23
eor r50,r50,r25
eor r55,r55,r27
rts

_R0e:
;Macro R
add r20,r56,r52
lsr r21,r20,0x19
imadd r21,r20,r19

;Macro R
add r22,r45,r57
lsr r23,r22,0x19
imadd r23,r22,r19

;Macro R
add r24,r50,r46
lsr r25,r24,0x19
imadd r25,r22,r19

;Macro R
add r26,r56,r51
lsr r27,r26,0x19
imadd r27,r26,r19

eor r44,r44,r21
eor r49,r49,r23
eor r54,r54,r25
eor r59,r59,r27
rts

_EXHANGE:
mov r20, r45
mov r21, r46
mov r45, r48
mov r46, r52
mov r48, r20
mov r52, r21

mov r20, r47
mov r21, r50
mov r47, r56
mov r50, r53
mov r56, r20
mov r53, r21

mov r20, r51
mov r21, r55
mov r51, r57
mov r55, r58
mov r57, r20
mov r58, r21
rts
