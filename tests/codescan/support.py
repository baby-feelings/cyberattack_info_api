"""CODESCAN のテストで共有する部品（tarball・ツール出力のサンプル・finding のファクトリ）。"""
import io
import tarfile
from datetime import UTC, datetime

from app.codescan.models import CodeFinding

_NOW = datetime.now(UTC)

SAMPLE_SEMGREP_JSON = {
    "results": [
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "REPO_ROOT/app/main.py",
            "start": {"line": 10},
            "end": {"line": 10},
            "extra": {
                "message": "Hardcoded password detected",
                "severity": "ERROR",
                "lines": 'PASSWORD = "hunter2"',
                "metadata": {
                    "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                    "owasp": ["A07:2021 - Identification and Authentication Failures"],
                },
            },
        },
    ],
}

# gitleaks のJSON出力サンプル。"Secret"フィールドに実際のシークレット値が
# 平文で含まれることに注意（_parse_gitleaks_resultsがこれを一切保存しないことを
# TestParseGitleaksResultsで検証する）
SAMPLE_GITLEAKS_JSON = [
    {
        "Description": "AWS Access Key",
        "StartLine": 5,
        "EndLine": 5,
        "RuleID": "aws-access-token",
        "File": "app/config.py",
        "Secret": "AKIAABCDEFGHIJKLMNOP",  # pragma: allowlist secret
        "Match": 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"',
    },
]



def make_finding(db_session, **kwargs) -> CodeFinding:
    defaults = {
        "repo_full_name": "baby-feelings/baby_grow",
        "file_path": "app/main.py",
        "line_start": 10,
        "line_end": 10,
        "rule_id": "python.lang.security.audit.hardcoded-password",
        "message": "Hardcoded password detected",
        "severity": "ERROR",
        "cwe_ids": ["CWE-798"],
        "owasp_categories": [],
        "code_snippet": 'PASSWORD = "hunter2"',
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "detected_at": _NOW,
        "resolved_at": None,
    }
    defaults.update(kwargs)
    record = CodeFinding(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


def make_tarball(files: dict[str, str], top_dir: str = "owner-repo-abcdef") -> bytes:
    """{相対パス: 内容} からGitHub tarball相当の.tar.gzバイト列を生成する。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel_path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"{top_dir}/{rel_path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()
