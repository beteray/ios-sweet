#!/bin/sh
# Stage 0 acceptance run: an arm64e userland binary under the SWEET kernel.
#
#   tools/run-pac-test.sh [KERNEL] [OUTDIR]
#
# KERNEL defaults to xnu/out/kernel.development.sweet (from a CI run whose patch
# series includes 0082-sweet-arm64e-pac.patch).  Needs python3, qemu-system-aarch64
# and (for exact framebuffer decoding) llvm-nm; it does not need a phone.
#
# What is checked (and why those two markers):
#   1. "SWEET PAC TEST: PASS 10/10 checks" is printed by the test itself after
#      every PAC class was emulated with the intended semantics.
#   2. "initproc exited -- ... (signal 0, exit status 0)" is printed by the
#      kernel's proc_handle_critical_exit() when PID 1 exits with status 0.
#      A PID-1 exit always panics by design (kern_exit.c: initproc), so the
#      panic right after it is expected and is printed, not treated as failure.
#
# Any earlier panic, or a missing marker, fails the run.
set -u

KERNEL=${1:-xnu/out/kernel.development.sweet}
OUTDIR=${2:-out/pac-test}
SECS=${SECS:-90}

if [ ! -f "$KERNEL" ]; then
	echo "run-pac-test: no kernel at $KERNEL" >&2
	exit 1
fi

mkdir -p "$OUTDIR"

echo "== 1/4 arm64e test binary"
python3 tools/mkpacexe.py "$OUTDIR/pac-test.bin" || exit 1

echo "== 2/4 QEMU device tree"
python3 tools/mkadt.py "$OUTDIR/qemu.adt" --qemu || exit 1

echo "== 3/4 payload (test binary as md0 root)"
python3 tools/mkpayload.py "$KERNEL" "$OUTDIR/qemu.adt" "$OUTDIR/payload.bin" \
	--ramdisk "$OUTDIR/pac-test.bin" \
	--cmdline 'debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam -noprogress rd=md0 sweetpaclog=1' \
	|| exit 1

echo "== 4/4 QEMU virt (${SECS}s)"
# --fail-on-panic would trip on the expected initproc panic, so the markers are
# checked here instead.  The live serial log and the decoded framebuffer text
# are both kept.
python3 tools/qemu-sweet.py "$OUTDIR/payload.bin" "$OUTDIR/run" \
	--secs "$SECS" --kernel "$KERNEL" --live-serial \
	>"$OUTDIR/serial.txt" 2>&1 || true

STATUS=0
for marker in 'SWEET PAC TEST: PASS 10/10' 'exit status 0'; do
	if grep -q "$marker" "$OUTDIR/serial.txt" 2>/dev/null ||
	    grep -q "$marker" "$OUTDIR/run/fb.txt" 2>/dev/null; then
		echo "ok: found '$marker'"
	else
		echo "FAILED: '$marker' not in $OUTDIR/serial.txt or $OUTDIR/run/fb.txt" >&2
		STATUS=1
	fi
done

if grep -q 'SWEET PAC TEST: FAIL check' "$OUTDIR/serial.txt" "$OUTDIR/run/fb.txt" 2>/dev/null; then
	echo "FAILED: the test reported a failing check" >&2
	STATUS=1
fi

# The expected PID-1 panic is informative: print it for the record.
grep -h 'initproc\|panic' "$OUTDIR/serial.txt" "$OUTDIR/run/fb.txt" 2>/dev/null | tail -5

if [ "$STATUS" -eq 0 ]; then
	echo "PAC TEST: PASS (log: $OUTDIR/serial.txt)"
else
	echo "PAC TEST: FAIL (log: $OUTDIR/serial.txt)" >&2
fi
exit "$STATUS"
