.section .text

.global _salsa20_8

_salsa20_8:

mov r3, 0x0
mov r58, Bor

FOR1:

; Bor[i] = Bout[i] = (B[i] ^ Bx[i]);
ldr r16,[r1,+r3]  ; Loads Bx[i]
ldr r12,[r0,+r3]  ; Loads B[i]
eor r12,r16,r12   ; B[i] ^ Bx[i]
str r12,[r2,+r3]  ; Stores the result in Bout[i]
str r12,[r58,+r3] ; Stores the result in Bor[i]
add r3,r3,4       ; Increments i

sub r12,r3,64     ; Bucle condition
bne FOR1

; Bout is catched in the CPU Registers
ldr r23,[r2,+0x0]
ldr r18,[r2,+0x1]
ldr r1, [r2,+0x2]
ldr r27,[r2,+0x3]
ldr r26,[r2,+0x4]
ldr r22,[r2,+0x5]
ldr r17,[r2,+0x6]
ldr r0, [r2,+0x7]
ldr r12,[r2,+0x8]
ldr r25,[r2,+0x9]
ldr r21,[r2,+0xa]
ldr r16,[r2,+0xb]
ldr r19,[r2,+0xc]
ldr r3, [r2,+0xd]
ldr r24,[r2,+0xe]
ldr r20,[r2,+0xf]

; The multiplication constants must be in CPU Registers
mov r60,128       ; 2^7
mov r61,512       ; 2^9
mov r62,8192      ; 2^13
mov r63,262144    ; 2^18

;INICIO BUCLE FOR
mov r59,0x4
FOR2:

;Macro R
add   r45,r19,r23
lsr   r46,r45,0x19
imadd r46,r45,r60
eor   r26,r26,r46

;Macro R
add r45,r18,r22
lsr r46,r45,0x19
imadd r46,r45,r60
eor r25,r25,r46

;Macro R
add r45,r17,r21
lsr r46,r45,0x19
imadd r46,r45,r60
eor r24,r24,r46

;Macro R
add r45,r16,r20
lsr r46,r45,0x19
imadd r46,r45,r60
eor r27,r27,r46

;Macro R
add r45,r26,r23
lsr r46,r45,0x17
imadd r46,r45,r60
eor r46,r12,r46

;Macro R
add r12,r25,r22
lsr r45,r12,0x17
imadd r45,r12,r61
eor r45,r3,r45

;Macro R
add r3,r24,r21
lsr r12,r3,0x17
imadd r12,r3,r61
eor r12,r1,r12

;Macro R
add r1,r27,r20
lsr r3,r1,0x17
imadd r3,r1,r61
eor r3,r0,r3

;Macro R
add r0,r46,r26
lsr r1,r0,0x13
imadd r1,r0,r62
eor r19,r1,r19

;Macro R
add r0,r45,r25
lsr r1,r0,0x13
imadd r1,r0,r62
eor r18,r1,r18

;Macro R
add r0,r12,r24
lsr r1,r0,0x13
imadd r1,r0,r62
eor r17,r1,r17

;Macro R
add r0,r3,r27
lsr r1,r0,0x13
imadd r1,r0,r62
eor r16,r1,r16

;Macro R
add r0,r19,r46
lsr r1,r0,0xe
imadd r1,r0,r63
eor r23,r1,r23

;Macro R
add r0,r18,r45
lsr r1,r0,0xe
imadd r1,r0,r63
eor r22,r1,r22

;Macro R
add r0,r17,r12
lsr r1,r0,0xe
imadd r1,r0,r63
eor r21,r1,r21

;Macro R
add r0,r16,r3
lsr r1,r0,0xe
imadd r1,r0,r63
eor r20,r1,r20

;Macro R
add r0,r23,r27
lsr r1,r0,0x19
imadd r1,r0,r60
eor r18,r1,r18

;Macro R
add r0,r22,r26
lsr r1,r0,0x19
imadd r1,r0,r60
eor r17,r1,r17

;Macro R
add r0,r21,r25
lsr r1,r0,0x19
imadd r1,r0,r60
eor r16,r1,r16

;Macro R
add r0,r20,r24
lsr r1,r0,0x19
imadd r1,r0,r60
eor r19,r1,r19

;Macro R
add r0,r18,r23
lsr r1,r0,0x17
imadd r1,r0,r61
eor r1,r1,r12

;Macro R
add r12,r17,r22
lsr r0,r12,0x17
imadd r0,r12,r61
eor r0,r0,r3

;Macro R
add r3,r16,r21
lsr r12,r3,0x17
imadd r12,r3,r61
eor r12,r12,r46

;Macro R
add r46,r19,r20
lsr r3,r46,0x17
imadd r3,r46,r61
eor r3,r3,r45

;Macro R
add r45,r1,r18
lsr r46,r45,0x13
imadd r46,r45,r62
eor r27,r46,r27

;Macro R
add r45,r0,r17
lsr r46,r45,0x13
imadd r46,r45,r62
eor r26,r46,r26

;Macro R
add r45,r12,r16
lsr r46,r45,0x13
imadd r46,r45,r62
eor r25,r46,r25

;Macro R
add r45,r3,r19
lsr r46,r45,0x13
imadd r46,r45,r62
eor r24,r46,r24

;Macro R
add r45,r27,r1
lsr r46,r45,0xe
imadd r46,r45,r63
eor r23,r46,r23

;Macro R
add r45,r26,r0
lsr r46,r45,0xe
imadd r46,r45,r63
eor r22,r46,r22

;Macro R
add r45,r25,r12
lsr r46,r45,0xe
imadd r46,r45,r63
eor r21,r46,r21

;Macro R
add r45,r24,r3
lsr r46,r45,0xe
imadd r46,r45,r63
eor r20,r46,r20

;SALTO DEL FOR2
sub r59,r59,1
bne FOR2

; Stores Bout
str r23,[r2,+0x0]
str r18,[r2,+0x1]
str r1, [r2,+0x2]
str r27,[r2,+0x3]
str r26,[r2,+0x4]
str r22,[r2,+0x5]
str r17,[r2,+0x6]
str r0, [r2,+0x7]
str r12,[r2,+0x8]
str r25,[r2,+0x9]
str r21,[r2,+0xa]
str r16,[r2,+0xb]
str r19,[r2,+0xc]
str r3, [r2,+0xd]
str r24,[r2,+0xe]
str r20,[r2,+0xf]

mov r0,0x0

FOR3:
; Bout[i] += Bor[i];
ldr r3,[r2,r0] ; Bout[i]
ldr r1,[r58,r0] ; Bor[i]
add r1,r3,r1   ; Bout[i] + Bor[i]
str r1,[r2,r0] ; Stores the restult in Bout[i]
add r0,r0,4    ; Increase i

sub r1,r0,64
bne FOR3

rts

.section .data

Bor:
.rept 16
.word
.endr
