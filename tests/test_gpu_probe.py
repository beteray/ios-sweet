"""Exercise the real patch source against instrumented, unchanged MMIO banks."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "xnu/patches/0082-sweet-gpu-probe.patch"


def new_source(text):
    marker = "+++ b/bsd/dev/sweet_gpu.c\n"
    body = text.split(marker, 1)[1]
    return "\n".join(line[1:] for line in body.splitlines()
                     if line.startswith("+") and not line.startswith("+++")) + "\n"


HARNESS = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "sweet_gpu.c"

static uint32_t gcc[0x90000 / 4], gpucc[0x9000 / 4];
static uint32_t gcc_before[0x90000 / 4], gpucc_before[0x9000 / 4];
static int mode, present, fail_map, maps;
static char logs[8192];
static size_t used;

int test_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(logs + used, sizeof(logs) - used, fmt, ap);
    va_end(ap);
    assert(n >= 0 && (size_t)n < sizeof(logs) - used);
    used += (size_t)n;
    return n;
}

int PE_parse_boot_argn(const char *name, void *value, int size)
{
    assert(strcmp(name, "sweetgpuprobe") == 0 && size == sizeof(mode));
    if (present) memcpy(value, &mode, sizeof(mode));
    return present;
}

vm_offset_t ml_io_map(vm_offset_t address, vm_size_t size)
{
    maps++;
    assert(maps <= 2);
    assert((address == 0x00100000 && size == sizeof(gcc)) ||
           (address == 0x05090000 && size == sizeof(gpucc)));
    if (maps == fail_map) return 0;
    if (address == 0x00100000 && size == sizeof(gcc)) return (vm_offset_t)gcc;
    assert(address == 0x05090000 && size == sizeof(gpucc));
    return (vm_offset_t)gpucc;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    int scenario = atoi(argv[1]);
    present = scenario != 0;
    mode = scenario == 1 ? 0 : scenario == 2 ? 2 : 1;
    fail_map = scenario == 3 ? 1 : scenario == 5 ? 2 : 0;
    gcc[0x71004 / 4] = scenario == 4 ? 0x80000001 : scenario == 7 ? 0 : 1;
    gpucc[0x106c / 4] = 0x80000000;
    gpucc[0x100c / 4] = 1;
    memcpy(gcc_before, gcc, sizeof(gcc));
    memcpy(gpucc_before, gpucc, sizeof(gpucc));
    sweet_gpu_probe();
    assert(memcmp(gcc_before, gcc, sizeof(gcc)) == 0);
    assert(memcmp(gpucc_before, gpucc, sizeof(gpucc)) == 0);
    if (scenario <= 2) assert(maps == 0);
    if (scenario == 3) assert(maps == 1 && strstr(logs, "GCC map failed"));
    if (scenario == 4) assert(maps == 1 && strstr(logs, "GPUCC not read"));
    if (scenario == 7) assert(maps == 1 && strstr(logs, "GPUCC not read"));
    if (scenario == 5) assert(maps == 2 && strstr(logs, "GPUCC map failed"));
    if (scenario == 6) {
        assert(maps == 2);
        assert(strstr(logs, "CX_GDSCR 0x80000000"));
        assert(strstr(logs, "GX_GDSCR 0x00000001"));
        assert(strstr(logs, "read-only snapshot"));
    }
    return 0;
}
'''


class GPUProbeTest(unittest.TestCase):
    def test_real_probe_guards_and_read_only_snapshot(self):
        self.assertTrue(PATCH.exists(), "GPU bootstrap patch 0082 is missing")
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "Run this kernel harness in WSL with cc")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            headers = {
                "sys/param.h": "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\ntypedef uintptr_t vm_offset_t; typedef size_t vm_size_t;\n",
                "sys/systm.h": "int test_log(const char *, ...);\n#define printf test_log\n",
                "pexpert/pexpert.h": "int PE_parse_boot_argn(const char *, void *, int);\n",
                "libkern/OSAtomic.h": "#define OSMemoryBarrier() __sync_synchronize()\n",
            }
            for name, content in headers.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            (root / "sweet_gpu.c").write_text(new_source(PATCH.read_text()))
            (root / "harness.c").write_text(HARNESS)
            binary = root / "probe-test"
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-DARM64_BOARD_CONFIG_SWEET", "-I", str(root),
                            str(root / "harness.c"), "-o", str(binary)], check=True)
            for scenario in range(8):
                with self.subTest(scenario=scenario):
                    subprocess.run([str(binary), str(scenario)], check=True)


if __name__ == "__main__":
    unittest.main()
