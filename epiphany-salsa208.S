/*-
 * Copyright 2013 Rafael Waldo Delgado Doblas,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Rafael Waldo Delgado Doblas Epiphany ASM implementation of Daniel J. Bernstein Salsa 20 8
 */

.section .text

.global _salsa20_8

_salsa20_8:

ldr r3, [r1,+0x0]
ldr r58,[r0,+0x0]
eor r58,r58,r3
mov r23,r58

ldr r3, [r1,0x1]
ldr r57,[r0,+0x1]
eor r57,r57,r3
mov r19,r57

ldr r3, [r1,0x2]
ldr r56,[r0,+0x2]
eor r56,r56,r3
mov r18,r56

ldr r3, [r1,0x3]
ldr r55,[r0,+0x3]
eor r55,r55,r3
mov r27,r55

ldr r3, [r1,0x4]
ldr r54,[r0,+0x4]
eor r54,r54,r3
mov r26,r54

ldr r3, [r1,0x5]
ldr r53,[r0,+0x5]
eor r53,r53,r3
mov r22,r53

ldr r3, [r1,0x6]
ldr r52,[r0,+0x6]
eor r52,r52,r3
mov r17,r52

ldr r3, [r1,0x7]
ldr r51,[r0,+0x7]
eor r51,r51,r3
mov r16,r51

ldr r3, [r1,+0x8]
ldr r50,[r0,+0x8]
eor r50,r50,r3
mov r12,r50

ldr r3, [r1,+0x9]
ldr r49,[r0,+0x9]
eor r49,r49,r3
mov r25,r49

ldr r3, [r1,+0xa]
ldr r48,[r0,+0xa]
eor r48,r48,r3
mov r21,r48

ldr r3, [r1,+0xb]
ldr r47,[r0,+0xb]
eor r47,r47,r3
str r47,[r2,+0xb]

ldr r3, [r1,+0xc]
ldr r46,[r0,+0xc]
eor r46,r46,r3
str r46,[r2,+0xc]

ldr r3, [r1,+0xd]
ldr r45,[r0,+0xd]
eor r45,r45,r3
str r45,[r2,+0xd]

ldr r3, [r1,+0xe]
ldr r44,[r0,+0xe]
eor r44,r44,r3
mov r24,r44
str r44,[r2,+0xe]

ldr r62,[r0,+0xf]
ldr r0, [r1,+0xf]
eor r62,r62,r0
mov r20,r62

mov r1,r46
mov r3,r47
mov r0,r45

; The multiplication constants must be in CPU Registers
mov r44,0x80 ; 2^7
mov r45,0x200 ; 2^9
mov r46,0x2000 ; 2^13
eor r47,r47,r47
movt r47,0x4 ; 2^18

mov r59,0x4
FOR:

;Macro R
add r60,r1,r23
lsr r61,r60,0x19
imadd r61,r60,r44
eor r26,r26,r61

;Macro R
add r60,r19,r22
lsr r61,r60,0x19
imadd r61,r60,r44
eor r25,r25,r61

;Macro R
add r60,r17,r21
lsr r61,r60,0x19
imadd r61,r60,r44
eor r24,r24,r61

;Macro R
add r60,r3,r20
lsr r61,r60,0x19
imadd r61,r60,r44
eor r27,r27,r61

;Macro R
add r60,r26,r23
lsr r61,r60,0x17
imadd r61,r60,r45
eor r61,r12,r61

;Macro R
add r12,r25,r22
lsr r60,r12,0x17
imadd r60,r12,r45
eor r60,r0,r60

;Macro R
add r0,r24,r21
lsr r12,r0,0x17
imadd r12,r0,r45
eor r12,r18,r12

;Macro R
add r18,r27,r20
lsr r0,r18,0x17
imadd r0,r18,r45
eor r0,r16,r0

;Macro R
add r16,r61,r26
lsr r18,r16,0x13
imadd r18,r16,r46
eor r1,r18,r1

;Macro R
add r16,r60,r25
lsr r18,r16,0x13
imadd r18,r16,r46
eor r19,r18,r19

;Macro R
add r16,r12,r24
lsr r18,r16,0x13
imadd r18,r16,r46
eor r17,r18,r17

;Macro R
add r16,r0,r27
lsr r18,r16,0x13
imadd r18,r16,r46
eor r3,r18,r3

;Macro R
add r16,r1,r61
lsr r18,r16,0xe
imadd r18,r16,r47
eor r23,r18,r23

;Macro R
add r16,r19,r60
lsr r18,r16,0xe
imadd r18,r16,r47
eor r22,r18,r22

;Macro R
add r16,r17,r12
lsr r18,r16,0xe
imadd r18,r16,r47
eor r21,r18,r21

;Macro R
add r16,r3,r0
lsr r18,r16,0xe
imadd r18,r16,r47
eor r20,r18,r20

;Macro R
add r16,r23,r27
lsr r18,r16,0x19
imadd r18,r16,r44
eor r19,r18,r19

;Macro R
add r16,r22,r26
lsr r18,r16,0x19
imadd r18,r16,r44
eor r17,r18,r17

;Macro R
add r16,r21,r25
lsr r18,r16,0x19
imadd r18,r16,r44
eor r3,r18,r3

;Macro R
add r16,r20,r24
lsr r18,r16,0x19
imadd r18,r16,r44
eor r1,r18,r1

;Macro R
add r16,r19,r23
lsr r18,r16,0x17
imadd r18,r16,r45
eor r18,r18,r12

;Macro R
add r12,r17,r22
lsr r16,r12,0x17
imadd r16,r12,r45
eor r16,r16,r0

;Macro R
add r0,r3,r21
lsr r12,r0,0x17
imadd r12,r0,r45
eor r12,r12,r61

;Macro R
add r61,r1,r20
lsr r0,r61,0x17
imadd r0,r61,r45
eor r0,r0,r60

;Macro R
add r60,r18,r19
lsr r61,r60,0x13
imadd r61,r60,r46
eor r27,r61,r27

;Macro R
add r60,r16,r17
lsr r61,r60,0x13
imadd r61,r60,r46
eor r26,r61,r26

;Macro R
add r60,r12,r3
lsr r61,r60,0x13
imadd r61,r60,r46
eor r25,r61,r25

;Macro R
add r60,r0,r1
lsr r61,r60,0x13
imadd r61,r60,r46
eor r24,r61,r24

;Macro R
add r60,r27,r18
lsr r61,r60,0xe
imadd r61,r60,r47
eor r23,r61,r23

;Macro R
add r60,r26,r16
lsr r61,r60,0xe
imadd r61,r60,r47
eor r22,r61,r22

;Macro R
add r60,r25,r12
lsr r61,r60,0xe
imadd r61,r60,r47
eor r21,r61,r21

;Macro R
add r60,r24,r0
lsr r61,r60,0xe
imadd r61,r60,r47
eor r20,r61,r20

sub r59,r59,1
bne FOR

ldr r44,[r2,+0xe]
ldr r45,[r2,+0xd]
ldr r46,[r2,+0xc]
ldr r47,[r2,+0xb]

add r23,r23,r58
add r19,r19,r57
add r18,r18,r56
add r27,r27,r55
add r26,r26,r54
add r22,r22,r53
add r17,r17,r52
add r16,r16,r51
add r12,r12,r50
add r25,r25,r49
add r21,r21,r48
add r3,r3,r47
add r1,r1,r46
add r0,r0,r45
add r24,r24,r44
add r20,r20,r62

str r23,[r2,+0x0]
str r19,[r2,+0x1]
str r18,[r2,+0x2]
str r27,[r2,+0x3]
str r26,[r2,+0x4]
str r22,[r2,+0x5]
str r17,[r2,+0x6]
str r16,[r2,+0x7]
str r12,[r2,+0x8]
str r25,[r2,+0x9]
str r21,[r2,+0xa]
str r3, [r2,+0xb]
str r1, [r2,+0xc]
str r0, [r2,+0xd]
str r24,[r2,+0xe]
str r20,[r2,+0xf]
rts
