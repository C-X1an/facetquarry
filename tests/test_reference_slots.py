"""Execute the actual reference allocation block with nonallocating shell probes."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReferenceAllocationSlots(unittest.TestCase):
    def setUp(self):
        self.bash = shutil.which('bash')
        if os.name == 'nt':
            candidate = Path('C:/Program Files/Git/bin/bash.exe')
            if candidate.is_file():
                self.bash = str(candidate)
        if not self.bash:
            self.skipTest('Bash unavailable; actual reference Bash control remains NOT RUN')
        temporary = ROOT / '.cache/tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        workflow = (ROOT / '.github/workflows/release-evidence.yml').read_text(encoding='utf-8')
        reference = workflow.split('\n  reference:\n', 1)[1].split('\n  codec:\n', 1)[0]
        start = reference.index('          test ! -e "$fq_image"')
        stop = reference.index('          cp -a "$GITHUB_WORKSPACE" "$fq_volume/source"', start)
        self.block = '\n'.join(line[10:] for line in reference[start:stop].splitlines())
        self.assertIn('fallocate -l 2300000000 "$fq_image"', self.block)
        self.assertIn('mkfs.ext4 -F -q "$fq_image"', self.block)
        self.assertIn('sudo -n mount -o loop "$fq_image" "$fq_volume"', self.block)

    def run_block(self, case):
        # These functions observe the real block's command order. They never
        # allocate, format, mount, unlink, or invoke a privileged subprocess.
        prefix = '''set -euo pipefail
fq_image="$PWD/image.img"
fq_volume="$PWD/volume"
RUNNER_TEMP="$PWD"
observe() { printf '%s\\n' "$*" >> "$PWD/calls.txt"; }
mkdir() { observe mkdir "$@"; }
mkfs.ext4() { observe mkfs.ext4 "$@"; }
sudo() { observe sudo "$@"; }
fallocate() {
  observe fallocate "$@"
  if test "$2" = 2400000000; then
    printf 'No space left on device\\n' >&2
    return 1
  fi
}
rm() { observe rm "$@"; }
'''
        return subprocess.run([self.bash, '--noprofile', '--norc', '-c', prefix + self.block],
                              cwd=case, text=True, capture_output=True, timeout=10)

    @staticmethod
    def identity(path):
        info = path.lstat()
        target = os.readlink(path) if path.is_symlink() else None
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and target is None else None
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, target, digest)

    def occupied(self, slot, kind):
        case = self.base / (slot + '-' + kind)
        case.mkdir()
        path = case / ('image.img' if slot == 'image' else 'volume')
        if kind == 'file':
            path.write_bytes(b'preexisting unrelated slot bytes must survive\n')
        elif kind == 'directory':
            path.mkdir()
            (path / 'keeper').write_bytes(b'original nested bytes')
        else:
            try:
                path.symlink_to(case / 'absent-target', target_is_directory=slot == 'volume')
            except OSError as error:
                self.skipTest('Dangling symlink fixture unavailable: ' + str(error))
        before = self.identity(path)
        result = self.run_block(case)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((case / 'calls.txt').exists(), 'allocation/format/mount command was reached')
        self.assertEqual(self.identity(path), before, 'occupied slot changed')
        self.assertFalse((case / 'absent-target').exists())

    def test_occupied_image_file_refuses_before_any_allocation_command(self):
        self.occupied('image', 'file')

    def test_occupied_image_directory_refuses_before_any_allocation_command(self):
        self.occupied('image', 'directory')

    def test_occupied_volume_file_refuses_before_any_allocation_command(self):
        self.occupied('volume', 'file')

    def test_occupied_volume_directory_refuses_before_any_allocation_command(self):
        self.occupied('volume', 'directory')

    def test_dangling_image_link_refuses_before_any_allocation_command(self):
        self.occupied('image', 'link')

    def test_dangling_volume_link_refuses_before_any_allocation_command(self):
        self.occupied('volume', 'link')

    def test_fresh_slots_reach_the_actual_allocation_order(self):
        result = self.run_block(self.base)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = (self.base / 'calls.txt').read_text().splitlines()
        self.assertEqual([line.split()[0] for line in lines],
                         ['mkdir', 'fallocate', 'mkfs.ext4', 'sudo', 'sudo', 'fallocate', 'rm'])
        self.assertIn('2300000000', lines[1])
        self.assertFalse((self.base / 'image.img').exists())
        self.assertFalse((self.base / 'volume').exists())


if __name__ == '__main__':
    unittest.main()
