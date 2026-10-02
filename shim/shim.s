@ U6-Enterprise AArch32 -> AArch64 boot shim.
@ Ubiquiti's U-Boot runs in AArch32 and only boots armv7 zImages (bootz), so
@ this zImage asks the TrustZone monitor to restart the core in AArch64 at the
@ arm64 kernel - the SIP call QSDK U-Boot's jump_kernel64() makes.
@ Entry from bootz: r0 = 0, r1 = machine id, r2 = device tree (caches off).
	.syntax unified
	.arm
	.arch	armv7-a
	.arch_extension sec
	.text
	.globl	_start
_start:
	.rept	8
	mov	r0, r0			@ zImage header: eight no-ops,
	.endr
	b	1f			@ a branch over the header,
	.word	0x016f2818		@ the magic bootz checks,
	.word	0			@ and the image start/end offsets.
	.word	_end - _start
1:	adr	r6, params
	str	r2, [r6]		@ x0 = device tree (high word stays 0)
	ldr	r0, kernel_entry
	str	r0, [r6, #72]		@ kernel_start
	dsb	sy
	movw	r0, #0x010f		@ SIP owner 2, service BOOT (1), cmd 0xf:
	movt	r0, #0x0200		@ switch EL1 to AArch64
	mov	r1, #0x12		@ arginfo: 2 args, arg0 a read-only buffer
	mov	r2, r6			@ arg0 = &kernel_params
	mov	r3, #80			@ arg1 = sizeof(kernel_params)
	mov	r4, #0
	mov	r5, #0
	smc	#0
	@ Only reached if the monitor refused: reset, so the AP falls back to stock.
	movw	r0, #0x0009		@ PSCI SYSTEM_RESET
	movt	r0, #0x8400
	smc	#0
2:	wfi
	b	2b

	.align	3
kernel_entry:
	.word	KERNEL_ENTRY
	.align	3
params:					@ QSDK kernel_params: u64 x0..x8, u64 kernel_start
	.space	80
_end:
