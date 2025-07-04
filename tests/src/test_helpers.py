import os
from pathlib import Path
from cve2stix.helper import clean_filesystem


def test_clean_filesystem():
    fspath = Path('./test_cleaner/')
    fp1 = fspath/"path/to/file1/file2.txt"
    fp1.parent.mkdir(parents=True, exist_ok=True)
    fp1.write_text("example")
    (fspath/"file0.json").write_text('{"is_json":true}')
    clean_filesystem(str(fspath))
    assert not fspath.exists() or not os.listdir(fspath), "file system should already be removed"