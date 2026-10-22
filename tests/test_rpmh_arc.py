"""Exercise the ARC level selector embedded in XNU patch 0083."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "xnu/patches/0083-sweet-gpu-cx-power.patch"


def added_source(text, path):
    marker = f"+++ b/{path}\n"
    body = text.split(marker, 1)[1].split("\ndiff --git ", 1)[0]
    return "\n".join(line[1:] for line in body.splitlines()
                     if line.startswith("+") and not line.startswith("+++")) + "\n"


HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "sweet_rpmh_arc.c"

int main(void)
{
    uint16_t levels[] = {0, 16, 48, 64, 128};
    uint32_t selector = 99;
    assert(sweet_rpmh_arc_choose_level(levels, 5, 49, &selector) == 0 && selector == 2);
    assert(sweet_rpmh_arc_choose_level(levels, 5, 65, &selector) == 0 && selector == 3);
    assert(sweet_rpmh_arc_choose_level(levels, 5, 130, &selector) == ERANGE);

    uint16_t padded[] = {16, 48, 64, 0, 0, 0};
    assert(sweet_rpmh_arc_choose_level(padded, 6, 49, &selector) == 0 && selector == 1);
    uint16_t corrupt_padding[] = {16, 48, 0, 64};
    assert(sweet_rpmh_arc_choose_level(corrupt_padding, 4, 49, &selector) == EINVAL);
    uint16_t descending[] = {16, 64, 48};
    assert(sweet_rpmh_arc_choose_level(descending, 3, 49, &selector) == EINVAL);
    assert(sweet_rpmh_arc_choose_level(levels, 0, 49, &selector) == EINVAL);
    assert(sweet_rpmh_arc_choose_level(levels, 17, 49, &selector) == EINVAL);
    assert(sweet_rpmh_arc_choose_level(levels, 5, 0, &selector) == EINVAL);
    return 0;
}
'''


class RPMHArcTest(unittest.TestCase):
    def test_cmd_db_arc_level_mapping(self):
        self.assertTrue(PATCH.exists(), "ARC GPU power patch 0083 is missing")
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "Run this C harness in WSL with cc")
        patch = PATCH.read_text()
        source = added_source(patch, "bsd/dev/sweet_rpmh_arc.c")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "sys").mkdir()
            (root / "sys/param.h").write_text(
                "#include <stdint.h>\n#include <stddef.h>\n"
                "typedef uintptr_t vm_offset_t; typedef size_t vm_size_t;\n")
            (root / "sys/errno.h").write_text("#include <errno.h>\n")
            (root / "sweet_rpmh_arc.c").write_text(source)
            (root / "harness.c").write_text(HARNESS)
            binary = root / "arc-test"
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-DARM64_BOARD_CONFIG_SWEET", "-I", str(root),
                            str(root / "harness.c"), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_patch_has_no_unresolved_arc_selector_name(self):
        patch = PATCH.read_text()
        self.assertIn("sweet_rpmh_arc_choose_level(const uint16_t *raw", patch)
        self.assertIn("sweet_rpmh_arc_choose_level(levels, nlevels", patch)
        self.assertNotRegex(patch, r"(?<!sweet_rpmh_)arc_choose_level\(levels, nlevels")


if __name__ == "__main__":
    unittest.main()
