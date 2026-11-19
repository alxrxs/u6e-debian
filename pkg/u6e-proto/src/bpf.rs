//! Classic BPF as the AP's root helpers' packet sockets run it: the opcodes
//! their programs use, an assembler that resolves labels into the forward
//! jumps the kernel takes, and an interpreter of that subset, which their
//! tests run the programs with as the kernel would.

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

// Classes, sizes, modes and operations (linux/filter.h).
pub const LD: u16 = 0x00;
pub const LDX: u16 = 0x01;
pub const ALU: u16 = 0x04;
pub const JMP: u16 = 0x05;
pub const RET: u16 = 0x06;
pub const W: u16 = 0x00;
pub const H: u16 = 0x08;
pub const B: u16 = 0x10;
pub const ABS: u16 = 0x20;
pub const IND: u16 = 0x40;
pub const LEN: u16 = 0x80;
pub const MSH: u16 = 0xa0;
pub const AND: u16 = 0x50;
pub const JEQ: u16 = 0x10;
pub const JGT: u16 = 0x20;
pub const JGE: u16 = 0x30;
pub const JSET: u16 = 0x40;

/// What an absolute load at these offsets reads instead of the packet
/// (SKF_AD_OFF + SKF_AD_*): the interface it came in on, whether the kernel
/// took a VLAN tag off it, and its packet type (`PACKET_OUTGOING` = 4 for
/// one the host sent).
pub const IFINDEX: u32 = 0xffff_f000 + 8;
pub const PKTTYPE: u32 = 0xffff_f000 + 4;
pub const VLAN_TAG_PRESENT: u32 = 0xffff_f000 + 48;
pub const PACKET_OUTGOING: u32 = 4;

/// One instruction, its jump (if any, when the test holds) to a label, or a
/// label. Labels are any comparable value, so a program built in parts can
/// name each part's labels apart.
pub enum Ins<L> {
    Op(u16, u32),
    Jump(u16, u32, L),
    Label(L),
}

/// Resolves the labels of `prog` into relative jumps. A jump goes forward,
/// at most 255 instructions; a label jumped to must exist.
pub fn assemble<L: Eq + Hash + Clone + Debug>(prog: &[Ins<L>]) -> Vec<libc::sock_filter> {
    let mut at = HashMap::new();
    let mut n = 0;
    for i in prog {
        match i {
            Ins::Label(l) => {
                at.insert(l.clone(), n);
            }
            _ => n += 1,
        }
    }
    let mut out = Vec::with_capacity(n);
    for i in prog {
        let (code, k, jt) = match i {
            Ins::Label(_) => continue,
            Ins::Op(code, k) => (*code, *k, 0),
            Ins::Jump(code, k, label) => {
                let to = *at
                    .get(label)
                    .unwrap_or_else(|| panic!("no label {label:?}"));
                let off = to - out.len() - 1;
                (*code, *k, u8::try_from(off).expect("a jump within 255"))
            }
        };
        out.push(libc::sock_filter { code, jt, jf: 0, k });
    }
    out
}

/// What the kernel knows of a packet beside its bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Meta {
    pub ifindex: u32,
    pub tagged: bool,
    pub pkttype: u32,
}

/// Runs `prog` on `pkt` as the kernel does: what it keeps of the packet (0:
/// drops it). A load past the packet's end drops it.
pub fn run(prog: &[libc::sock_filter], pkt: &[u8], meta: Meta) -> u32 {
    let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
    let load = |at: usize, n: usize| -> Option<u32> {
        Some(
            pkt.get(at..at.checked_add(n)?)?
                .iter()
                .fold(0, |v, b| v << 8 | u32::from(*b)),
        )
    };
    loop {
        let i = prog[pc];
        pc += 1;
        let size = match i.code & 0x18 {
            H => 2,
            B => 1,
            _ => 4,
        };
        match i.code & 0x07 {
            LD if i.k == IFINDEX => a = meta.ifindex,
            LD if i.k == PKTTYPE => a = meta.pkttype,
            LD if i.k == VLAN_TAG_PRESENT => a = u32::from(meta.tagged),
            LD if i.code & 0xe0 == LEN => a = pkt.len() as u32,
            LD => {
                let at = if i.code & 0xe0 == IND { x + i.k } else { i.k };
                let Some(v) = load(at as usize, size) else {
                    return 0;
                };
                a = v;
            }
            LDX => {
                let Some(v) = load(i.k as usize, 1) else {
                    return 0;
                };
                x = (v & 0x0f) * 4;
            }
            ALU => a &= i.k,
            JMP => {
                let hit = match i.code & 0xf0 {
                    JEQ => a == i.k,
                    JGT => a > i.k,
                    JGE => a >= i.k,
                    JSET => a & i.k != 0,
                    c => panic!("jump {c:#x}"),
                };
                pc += usize::from(if hit { i.jt } else { i.jf });
            }
            RET => return i.k,
            c => panic!("class {c:#x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ins::{Jump, Label, Op};

    #[test]
    fn labels_become_forward_jumps() {
        let prog = assemble(&[
            Op(LD | B | ABS, 0),
            Jump(JMP | JEQ, 7, ("a", 1)),
            Jump(JMP | JGT, 7, ("a", 2)),
            Op(RET, 0),
            Label(("a", 1)),
            Op(RET, 1),
            Label(("a", 2)),
            Op(RET, 2),
        ]);
        assert_eq!((prog[1].jt, prog[2].jt), (2, 2));
        let meta = Meta::default();
        assert_eq!(run(&prog, &[7], meta), 1);
        assert_eq!(run(&prog, &[9], meta), 2);
        assert_eq!(run(&prog, &[3], meta), 0);
        // Past the end: dropped.
        assert_eq!(run(&prog, &[], meta), 0);
    }

    #[test]
    fn the_kernels_own_fields_are_read() {
        let prog = assemble::<&str>(&[
            Op(LD | ABS, PKTTYPE),
            Jump(JMP | JEQ, PACKET_OUTGOING, "out"),
            Op(LD | ABS, IFINDEX),
            Op(RET, 0),
            Label("out"),
            Op(RET, 99),
        ]);
        let out = Meta {
            pkttype: PACKET_OUTGOING,
            ..Meta::default()
        };
        assert_eq!(run(&prog, &[], out), 99);
        assert_eq!(run(&prog, &[], Meta::default()), 0);
    }
}
