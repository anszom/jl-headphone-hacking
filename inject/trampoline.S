
.equ    f_readnextdir_body, f_readnextdir+6

.text
.p2align 1
.global f_readnextdir_trampoline
f_readnextdir_trampoline:
	.byte   0x7f, 0x04        /* [--sp] = {rets, r15-r4} */
	.byte   0xe2, 0x90        /* sp += -64               */
	.byte   0x3b, 0x16        /* r11 = r3                */
	goto    f_readnextdir_body
