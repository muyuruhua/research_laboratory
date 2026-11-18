import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from finalize_mock_archive import finalize


class FinalizeMockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stats = self.root / 'stats.json'
        self.stats.write_text(json.dumps({'effective_config': {'seed': 7}}))

    def config(self, parent):
        path = self.root / parent / 'out-test' / 'run-config.jsonl'
        path.parent.mkdir(parents=True)
        path.write_text('{"phase":"start"}\n{"phase":"end"}\n')
        return path

    def test_nested_run_with_spaces_packages_configuration_and_stats(self):
        self.config('subject with spaces')
        archive = finalize(self.root, 'out-test', self.stats)
        with tarfile.open(archive) as stream:
            config = stream.extractfile('out-test/run-config.jsonl').read().decode()
            self.assertEqual([json.loads(x)['mock_gateway']['seed'] for x in config.splitlines()], [7, 7])
            self.assertIsNotNone(stream.extractfile('out-test/mock-stats.json'))

    def test_no_config_rejects_without_replacing_existing_archive(self):
        archive = self.root / 'out-test.tar.gz'
        archive.write_bytes(b'original')
        with self.assertRaisesRegex(ValueError, 'found 0'):
            finalize(self.root, 'out-test', self.stats)
        self.assertEqual(archive.read_bytes(), b'original')

    def test_ambiguous_config_rejects(self):
        self.config('first')
        self.config('second')
        with self.assertRaisesRegex(ValueError, 'found 2'):
            finalize(self.root, 'out-test', self.stats)

    def test_bad_stats_leave_raw_configuration_unchanged(self):
        config = self.config('subject')
        original = config.read_bytes()
        self.stats.write_text('{}')
        with self.assertRaises(KeyError):
            finalize(self.root, 'out-test', self.stats)
        self.assertEqual(config.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
