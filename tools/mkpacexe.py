#!/usr/bin/env python3
"""Build the stage-0 PAC test: a static arm64e Mach-O that PID 1 runs.

What it proves, in one boot of the SWEET kernel in QEMU:

  * the kernel accepts an arm64e executable (cpusubtype CPU_SUBTYPE_ARM64E with
    the versioned ptrauth ABI bit), which stock grade_binary() rejects on a
    non-arm64e host;
  * PACIBSP in the prologue does not fault (HINT space, architecturally a NOP);
  * the trapped PAC encodings are emulated with the "no signature" semantics:
      PACIA/PACIB/PACDA (Rd := Rn), AUTIA (Rd := Rn), XPACI (unchanged),
      PACIZA/AUTIZA (Rd := 0), BRAA (br), BLRAAZ (blr, x30 := pc+4),
      RETAA (ret) -- each checked by comparing registers or by where the jump
    lands;
  * the process then exits with status 0.  A PID-1 exit panics the kernel by
    design; proc_handle_critical_exit() prints "initproc exited -- ...
    (signal 0, exit status 0)", which the runner checks.  That line is the
    machine-checkable proof of exit code 0.

No assembler is required: the code is emitted as instruction words.  The PAC
encodings come from the same verified table as the kernel decoder
(research/tools/pacgen.py, ground truth: binutils aarch64-tbl.h).

Usage: mkpacexe.py OUT.bin [--subtype arm64e|arm64]

--subtype arm64 emits the same PAC code with CPU_SUBTYPE_ARM64_ALL: the kernel
accepts such a binary (grade 9) but still SIGILLs on the first PAC instruction,
which is the control run that proves the trap is real.
"""
import io
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mkinit  # noqa: E402  (Mach-O layout + ad-hoc signature helpers)

BASE, SEG, CODE_OFF = mkinit.BASE, mkinit.SEG, mkinit.CODE_OFF
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_PTRAUTH_ABI = 0x80000000
PTRAUTH_ABI_VERSION = 1          # bits 24..27; clang -arch arm64e emits this
CPUSUBTYPE_ARM64E = CPU_SUBTYPE_PTRAUTH_ABI | (PTRAUTH_ABI_VERSION << 24) | CPU_SUBTYPE_ARM64E
CPUSUBTYPE_ARM64 = 0             # CPU_SUBTYPE_ARM64_ALL, no ptrauth ABI bits

SYS_exit, SYS_write, SYS_open, SYS_select = 1, 4, 5, 93
O_RDWR = 2


# ---------------------------------------------------------------- assembler
def movz(rd, imm16, hw=0):
    return 0xD2800000 | (hw << 21) | (imm16 << 5) | rd


def movk(rd, imm16, hw=0):
    return 0xF2800000 | (hw << 21) | (imm16 << 5) | rd


def mov_const(rd, val):
    out = [movz(rd, val & 0xFFFF, 0)]
    for hw in (1, 2, 3):
        part = (val >> (16 * hw)) & 0xFFFF
        if part:
            out.append(movk(rd, part, hw))
    return out


def add_imm(rd, rn, imm12):
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd


def sub_reg(rd, rn, rm):
    return 0xCB000000 | (rm << 16) | (rn << 5) | rd


def cmp_reg(rn, rm):
    """SUBS XZR, Xn, Xm"""
    return 0xEB000000 | (rm << 16) | (rn << 5) | 31


def b_cond(cond, offset_words):
    return 0x54000000 | ((offset_words & 0x7FFFF) << 5) | cond


def b(offset_words):
    return 0x14000000 | (offset_words & 0x3FFFFFF)


def bl(offset_words):
    return 0x94000000 | (offset_words & 0x3FFFFFF)


def adr(rd, byte_offset):
    imm21 = byte_offset & 0x1FFFFF
    return 0x10000000 | ((imm21 & 3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5) | rd


def svc():
    return 0xD4000001


NOP, RET = 0xD503201F, 0xD65F03C0
COND_NE, COND_CS, COND_EQ, COND_HS = 1, 2, 0, 2
MOV_X0_ZERO = movz(0, 0)
MOV_X16_EXIT = movz(16, SYS_exit)
MOV_X16_WRITE = movz(16, SYS_write)
MOV_X16_OPEN = movz(16, SYS_open)


def pacia(rd, rn):
    return 0xDAC10000 | (rn << 5) | rd


def pacib(rd, rn):
    return 0xDAC10400 | (rn << 5) | rd


def pacda(rd, rn):
    return 0xDAC10800 | (rn << 5) | rd


def autia(rd, rn):
    return 0xDAC11000 | (rn << 5) | rd


def paciza(rd):
    return 0xDAC123E0 | rd


def autiza(rd):
    return 0xDAC133E0 | rd


def xpaci(rd):
    return 0xDAC143E0 | rd


def braa(rn, rm):
    return 0xD71F0800 | (rm << 16) | (rn << 5)


def brab(rn, rm):
    return 0xD71F0C00 | (rm << 16) | (rn << 5)


def blraaz(rn):
    return 0xD63F081F | (rn << 5)


def retaa():
    return 0xD65F0BFF


PACIBSP = 0xD503237F          # HINT space: NOP on ARMv8.2


class Program:
    def __init__(self):
        self.code = []
        self.labels = {}
        self.fixups = []      # (index, kind, label, extra)

    def emit(self, *words):
        for w in words:
            assert 0 <= w <= 0xFFFFFFFF, hex(w)
            self.code.append(w)

    def label(self, name):
        assert name not in self.labels, name
        self.labels[name] = len(self.code)

    def _fix(self, index, kind, label, extra=None):
        self.fixups.append((index, kind, label, extra))

    def adr(self, rd, label):
        self._fix(len(self.code), 'adr', label, rd)
        self.code.append(0)

    def b(self, label):
        self._fix(len(self.code), 'b', label)
        self.code.append(0)

    def bl(self, label):
        self._fix(len(self.code), 'bl', label)
        self.code.append(0)

    def bcond(self, cond, label):
        self._fix(len(self.code), 'bcond', label, cond)
        self.code.append(0)

    def resolve(self):
        for index, kind, label, extra in self.fixups:
            target = self.labels[label]
            delta_words = target - index
            if kind == 'adr':
                self.code[index] = adr(extra, delta_words * 4)
            elif kind == 'b':
                self.code[index] = b(delta_words)
            elif kind == 'bl':
                self.code[index] = bl(delta_words)
            elif kind == 'bcond':
                self.code[index] = b_cond(extra, delta_words)
            else:
                raise AssertionError(kind)


def build_program():
    p = Program()

    def write_string(label):
        """bl target: write(x19, label, label_end - label)"""
        p.adr(1, label)
        p.adr(2, label + '_end')
        p.emit(sub_reg(2, 2, 1), MOV_X16_WRITE, svc(), RET)

    p.label('_start')
    p.emit(PACIBSP)                       # prologue hint; must not fault

    # open /dev/console -> x19
    p.adr(0, 'path')
    p.emit(movz(1, O_RDWR), movz(2, 0), MOV_X16_OPEN, svc())
    p.bcond(COND_CS, 'hang')
    p.emit(add_imm(19, 0, 0))             # x19 = x0 (fd)
    p.bl('write_banner')
    # Give the runner a window to snapshot the banner before a PAC fault (on an
    # unpatched kernel) or before the PID-1 exit panic (on a patched one).
    p.adr(4, 'sleep_tv')
    p.emit(movz(0, 0), movz(1, 0), movz(2, 0), movz(3, 0), movz(16, SYS_select), svc())

    # x9 = 0x1122334455667788
    p.emit(*mov_const(9, 0x1122334455667788))

    # 1: PACIA x10, x9 -> x10 == x9
    p.emit(pacia(10, 9), cmp_reg(10, 9))
    p.bcond(COND_NE, 'fail1')
    # 2: PACIB x11, x9 -> x11 == x9
    p.emit(pacib(11, 9), cmp_reg(11, 9))
    p.bcond(COND_NE, 'fail2')
    # 3: PACDA x12, x9 -> x12 == x9
    p.emit(pacda(12, 9), cmp_reg(12, 9))
    p.bcond(COND_NE, 'fail3')
    # 4: AUTIA x13, x12 -> x13 == x9 (no signature to strip)
    p.emit(autia(13, 12), cmp_reg(13, 9))
    p.bcond(COND_NE, 'fail4')
    # 5: XPACI x13 -> unchanged
    p.emit(xpaci(13), cmp_reg(13, 9))
    p.bcond(COND_NE, 'fail5')
    # 6: PACIZA x14 -> 0
    p.emit(paciza(14), cmp_reg(14, 31))
    p.bcond(COND_NE, 'fail6')
    # 7: AUTIZA x15 -> 0
    p.emit(autiza(15), cmp_reg(15, 31))
    p.bcond(COND_NE, 'fail7')

    # 8: BRAA x16, x9 -> jumps to braa_ok
    p.adr(16, 'braa_ok')
    p.emit(braa(16, 9))
    p.b('fail8')                          # not reached when BRAA executes
    p.label('braa_ok')

    # 9: BLRAAZ x17 -> jumps to blr_ok, x30 == address after the BLRAAZ
    p.adr(17, 'blr_ok')
    p.emit(blraaz(17))
    p.label('after_blraa')
    p.b('fail9')                          # only reached if BLRAAZ fell through
    p.label('blr_ok')
    p.adr(18, 'after_blraa')
    p.emit(cmp_reg(30, 18))
    p.bcond(COND_NE, 'fail9')

    # 10: RETAA -> pc := x30
    p.adr(30, 'ret_ok')
    p.emit(retaa())
    p.b('fail10')
    p.label('ret_ok')

    p.bl('write_pass')
    # Stay alive for a few seconds so a mid-run framebuffer snapshot can show
    # the PASS line (a PID-1 exit immediately panics and redraws the screen).
    p.adr(4, 'sleep_tv')
    p.emit(movz(0, 0), movz(1, 0), movz(2, 0), movz(3, 0), movz(16, SYS_select), svc())
    p.emit(MOV_X0_ZERO, MOV_X16_EXIT, svc())

    p.label('hang')
    p.b('hang')

    # ---- console write helpers ----
    p.label('write_banner')
    write_string('banner')
    p.label('write_pass')
    write_string('pass')

    # failure stubs
    for i in range(1, 11):
        p.label('fail%d' % i)
        write_string('fail%d_msg' % i)
        p.emit(movz(0, 1), MOV_X16_EXIT, svc())

    # ---- data ----
    def data(label, text):
        p.label(label)
        raw = text.encode()
        raw += b'\0' * (-len(raw) % 4)      # keep every label word aligned
        words = []
        for k in range(0, len(raw), 4):
            words.append(struct.unpack('<I', raw[k:k + 4])[0])
        p.emit(*words)
        p.label(label + '_end')

    data('path', '/dev/console\0\0\0\0')
    p.label('sleep_tv')                  # struct timeval {10 s, 0 us}
    p.emit(10, 0, 0, 0)
    banner = ('SWEET PAC TEST: arm64e binary running, prologue PACIBSP ok\n')
    data('banner', banner)
    data('pass', 'SWEET PAC TEST: PASS 10/10 checks, exit status 0\n')
    for i in range(1, 11):
        msg = 'SWEET PAC TEST: FAIL check %d\n' % i
        data('fail%d_msg' % i, msg)

    p.resolve()
    return p


def main():
    out = sys.argv[1]
    subtype = 'arm64e'
    if '--subtype' in sys.argv:
        subtype = sys.argv[sys.argv.index('--subtype') + 1]
    if subtype not in ('arm64e', 'arm64'):
        raise SystemExit('--subtype must be arm64e or arm64')
    cpusubtype = CPUSUBTYPE_ARM64E if subtype == 'arm64e' else CPUSUBTYPE_ARM64
    prog = build_program()
    raw = b''.join(struct.pack('<I', w) for w in prog.code)
    assert CODE_OFF + len(raw) <= SEG, 'code does not fit one 16K page'

    sect = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', BASE + CODE_OFF,
                       len(raw), CODE_OFF, 3, 0, 0, mkinit.S_ATTR_CODE, 0, 0, 0)
    sig_size = len(mkinit.code_signature(bytes(SEG), SEG, SEG, None))
    thread = struct.pack('<IIII', mkinit.LC_UNIXTHREAD,
                         16 + 4 * mkinit.ARM_THREAD_STATE64_COUNT,
                         mkinit.ARM_THREAD_STATE64, mkinit.ARM_THREAD_STATE64_COUNT)
    state = [0] * 33
    state[32] = BASE + CODE_OFF + 0            # _start is the first instruction
    thread += struct.pack('<33QII', *state, 0, 0)
    cmds = [
        mkinit.segment('__PAGEZERO', 0, BASE, 0, 0, 0),
        mkinit.segment('__TEXT', BASE, SEG, 0, SEG, mkinit.VM_PROT_R | mkinit.VM_PROT_X, [sect]),
        mkinit.segment('__LINKEDIT', BASE + SEG, SEG, SEG, sig_size, mkinit.VM_PROT_R),
        thread,
        struct.pack('<4I', mkinit.LC_CODE_SIGNATURE, 16, SEG, sig_size),
    ]
    lc = b''.join(cmds)
    header = struct.pack('<8I', mkinit.MH_MAGIC_64, mkinit.CPU_TYPE_ARM64, cpusubtype,
                         mkinit.MH_EXECUTE, len(cmds), len(lc), mkinit.MH_NOUNDEFS, 0)
    assert 32 + len(lc) <= CODE_OFF
    image = bytearray(SEG)
    image[:32 + len(lc)] = header + lc
    image[CODE_OFF:CODE_OFF + len(raw)] = raw
    sig = mkinit.code_signature(bytes(image), SEG, SEG, None)
    assert len(sig) == sig_size
    blob = bytes(image) + sig
    with io.open(out, 'wb') as fh:
        fh.write(blob)
    print('%s: %d bytes, %d instructions, cpusubtype %#x'
          % (out, len(blob), len(prog.code), cpusubtype))


if __name__ == '__main__':
    main()
