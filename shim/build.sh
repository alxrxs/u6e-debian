#!/bin/bash
# Build shim.bin for an arm64 kernel entered at $1 (default 0x41000000).
set -euo pipefail
cd "$(dirname "$0")"
X=arm-linux-gnueabihf-
${X}as --defsym KERNEL_ENTRY="${1:-0x41000000}" -o shim.o shim.s
${X}ld -Ttext=0 -o shim.elf shim.o
${X}objcopy -O binary shim.elf shim.bin
rm -f shim.o shim.elf
