"""app.codescan.iac_rules（Firebase ルール・Dockerfile・docker-compose の診断）のテスト。"""
from app.codescan import iac_rules as r


def _rules(issues):
    return [i.rule for i in issues]


class TestFirebaseRules:
    def test_open_write_without_authentication_is_an_error(self):
        issues = r.check_firebase_rules(
            "service cloud.firestore {\n  match /{document=**} {\n"
            "    allow read, write: if true;\n  }\n}\n",
        )

        assert _rules(issues) == ["firebase-open-write"]
        assert issues[0].severity == r.ERROR
        assert issues[0].line == 3
        assert "request.auth" in issues[0].message  # 修正方法を示す
        assert issues[0].cwe == "CWE-862"

    def test_open_read_only_is_a_warning(self):
        issues = r.check_firebase_rules("allow read: if true;")
        assert [(i.rule, i.severity) for i in issues] == [("firebase-open-read", r.WARNING)]

    def test_create_update_delete_count_as_writes(self):
        for op in ("create", "update", "delete", "write"):
            issues = r.check_firebase_rules(f"allow {op}: if true;")
            assert _rules(issues) == ["firebase-open-write"]

    def test_a_condition_spread_over_lines_is_still_read(self):
        text = "allow write:\n  if\n   true;"
        assert _rules(r.check_firebase_rules(text)) == ["firebase-open-write"]

    def test_test_mode_rules_with_an_expiry_are_flagged(self):
        issues = r.check_firebase_rules(
            "allow read, write: if request.time < timestamp.date(2026, 11, 30);",
        )
        assert [(i.rule, i.severity) for i in issues] == [("firebase-test-mode", r.ERROR)]

    def test_any_signed_in_user_can_write_is_a_warning(self):
        issues = r.check_firebase_rules("allow write: if request.auth != null;")
        assert [(i.rule, i.severity) for i in issues] == [("firebase-any-user-write", r.WARNING)]

    def test_signed_in_read_and_owner_checks_are_fine(self):
        text = (
            "allow read: if request.auth != null;\n"
            "allow write: if request.auth != null && request.auth.uid == userId;\n"
            "allow read, write: if false;\n"
            "allow get;\n"
        )
        assert r.check_firebase_rules(text) == []

    def test_no_rules_no_issues(self):
        assert r.check_firebase_rules("") == []


class TestRealtimeDatabaseRules:
    def test_open_read_and_write(self):
        text = '{\n  "rules": {\n    ".read": true,\n    ".write": "true"\n  }\n}'
        issues = r.check_realtime_db_rules(text)

        assert [(i.rule, i.line) for i in issues] == [
            ("firebase-open-read", 3), ("firebase-open-write", 4),
        ]

    def test_conditions_are_fine(self):
        assert r.check_realtime_db_rules('{"rules": {".read": "auth != null"}}') == []


class TestFirebaseJson:
    def test_publishing_the_repository_root_is_an_error(self):
        for value in (".", "./", ""):
            issues = r.check_firebase_json(f'{{"hosting": {{\n  "public": "{value}"\n}}}}')
            assert _rules(issues) == ["firebase-hosting-public-root"], value
            assert issues[0].line == 2

    def test_a_build_directory_is_fine(self):
        assert r.check_firebase_json('{"hosting": {"public": "build/web"}}') == []


class TestDockerfile:
    GOOD = (
        "FROM python:3.13-slim\nRUN useradd -m app\nUSER app\nCOPY . /app\n"
    )

    def test_a_well_formed_dockerfile_has_no_issues(self):
        assert r.check_dockerfile(self.GOOD) == []

    def test_running_as_root_is_flagged_on_the_last_stage(self):
        issues = r.check_dockerfile("FROM python:3.13-slim\nCOPY . /app\n")
        assert [(i.rule, i.line) for i in issues] == [("dockerfile-root-user", 1)]
        assert "USER" in issues[0].message

    def test_an_explicit_root_user_is_flagged(self):
        assert _rules(r.check_dockerfile("FROM python:3.13-slim\nUSER root\n")) == [
            "dockerfile-root-user",
        ]

    def test_only_the_last_stage_decides_the_user(self):
        text = (
            "FROM node:24 AS build\nRUN npm ci\n"
            "FROM nginx:1.27\nRUN useradd -m app\nUSER app\n"
        )
        assert r.check_dockerfile(text) == []

    def test_latest_and_missing_tags_are_flagged(self):
        issues = r.check_dockerfile("FROM python\nUSER app\nFROM node:latest\nUSER app\n")
        assert _rules(issues) == ["dockerfile-latest-tag", "dockerfile-latest-tag"]

    def test_pinned_images_scratch_stage_aliases_and_args_are_not_flagged(self):
        text = (
            "FROM python:3.13-slim@sha256:abc AS base\nFROM base AS final\n"
            "FROM scratch\nFROM $BASE_IMAGE\nFROM localhost:5000/team/app:1.2\nUSER app\n"
        )
        assert r.check_dockerfile(text) == []

    def test_registry_with_a_port_but_no_tag_is_flagged(self):
        assert _rules(r.check_dockerfile("FROM localhost:5000/team/app\nUSER app\n")) == [
            "dockerfile-latest-tag",
        ]

    def test_copying_secret_files_is_an_error(self):
        for source in (".env", ".env.production", "id_rsa", "server.pem", "credentials.json",
                       "config/serviceAccount-prod.json", ".npmrc"):
            issues = r.check_dockerfile(f"FROM python:3.13-slim\nCOPY {source} /app/\nUSER app\n")
            assert _rules(issues) == ["dockerfile-secret-copy"], source
            assert issues[0].severity == r.ERROR

    def test_copying_ordinary_files_is_fine(self):
        text = "FROM python:3.13-slim\nCOPY requirements.txt .env.example.md /app/\nUSER app\n"
        assert r.check_dockerfile(text) == []

    def test_literal_secrets_in_env_and_arg_are_errors_and_the_value_is_hidden(self):
        text = (
            "FROM python:3.13-slim\nUSER app\n"
            "ENV DB_PASSWORD=hunter2 PORT=8080\nARG API_KEY=abc123\nENV SECRET_TOKEN topsecret\n"
        )
        issues = r.check_dockerfile(text)

        assert _rules(issues) == ["dockerfile-secret-env"] * 3
        assert [i.snippet for i in issues] == [
            "ENV DB_PASSWORD=***", "ARG API_KEY=***", "ENV SECRET_TOKEN=***",
        ]
        # 値は、メッセージにもスニペットにも残さない
        assert not any(v in i.message + i.snippet for i in issues
                       for v in ("hunter2", "abc123", "topsecret"))

    def test_secrets_without_a_literal_value_are_fine(self):
        text = (
            "FROM python:3.13-slim\nUSER app\nARG GITHUB_TOKEN\n"
            "ENV API_KEY=${API_KEY}\nENV PORT=1\n"
        )
        assert r.check_dockerfile(text) == []

    def test_pipe_to_shell_is_flagged(self):
        text = "FROM python:3.13-slim\nUSER app\nRUN curl -fsSL https://x.sh | sh\n"
        assert _rules(r.check_dockerfile(text)) == ["dockerfile-pipe-to-shell"]

    def test_continuation_lines_are_joined(self):
        text = (
            "FROM python:3.13-slim\nUSER app\n"
            "RUN apt-get update && \\\n    curl -fsSL https://x.sh | bash\n"
        )
        issues = r.check_dockerfile(text)
        assert [(i.rule, i.line) for i in issues] == [("dockerfile-pipe-to-shell", 3)]

    def test_comments_and_blank_lines_are_ignored_and_empty_input_is_clean(self):
        assert r.check_dockerfile("# FROM python\n\n") == []
        assert r.check_dockerfile("") == []


class TestDockerCompose:
    def test_privileged_and_docker_socket_and_host_network(self):
        text = (
            "services:\n  app:\n    privileged: true\n    network_mode: host\n"
            "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        assert _rules(r.check_docker_compose(text)) == [
            "compose-privileged", "compose-host-network", "compose-docker-sock",
        ]

    def test_dangerous_capabilities_only_under_cap_add(self):
        text = "services:\n  app:\n    cap_add:\n      - SYS_ADMIN\n      - ALL\n"
        assert _rules(r.check_docker_compose(text)) == ["compose-dangerous-capability"] * 2
        assert r.check_docker_compose("services:\n  app:\n    command:\n      - all\n") == []

    def test_databases_published_to_every_interface_are_errors(self):
        text = (
            "services:\n  db:\n    ports:\n"
            '      - "5432:5432"\n      - 6379:6379\n      - "0.0.0.0:3306:3306"\n'
        )
        issues = r.check_docker_compose(text)

        assert _rules(issues) == ["compose-exposed-port"] * 3
        assert "PostgreSQL" in issues[0].message

    def test_loopback_bound_and_ordinary_ports_are_fine(self):
        text = (
            "services:\n  web:\n    ports:\n"
            '      - "127.0.0.1:5432:5432"\n      - "80:80"\n      - "443:443"\n'
        )
        assert r.check_docker_compose(text) == []

    def test_a_database_remapped_to_another_host_port_is_still_flagged(self):
        assert _rules(r.check_docker_compose('    ports:\n      - "15432:5432/tcp"\n')) == [
            "compose-exposed-port",
        ]

    def test_literal_secrets_are_warnings_and_values_are_hidden(self):
        text = (
            "services:\n  db:\n    environment:\n"
            "      POSTGRES_PASSWORD: hunter2\n      - API_TOKEN=abc123\n"
            "      POSTGRES_USER: app\n"
        )
        issues = r.check_docker_compose(text)

        assert _rules(issues) == ["compose-secret-env"] * 2
        assert [i.snippet for i in issues] == ["POSTGRES_PASSWORD: ***", "API_TOKEN: ***"]
        assert not any(v in i.message + i.snippet for i in issues for v in ("hunter2", "abc123"))

    def test_obvious_placeholders_are_not_treated_as_secrets(self):
        text = (
            "services:\n  app:\n    environment:\n"
            "      API_KEY: zap-scan-dummy-key\n      - DB_PASSWORD=changeme\n"
            "      SESSION_SECRET: <your-secret>\n"
        )
        assert r.check_docker_compose(text) == []
        dockerfile = "FROM python:3.13-slim\nUSER app\nENV API_KEY=example-key\n"
        assert r.check_dockerfile(dockerfile) == []

    def test_variable_references_and_secret_files_are_fine(self):
        text = (
            "services:\n  db:\n    environment:\n"
            "      POSTGRES_PASSWORD: ${DB_PASSWORD}\n"
            "      POSTGRES_PASSWORD_FILE: /run/secrets/pw\n"
            "      - API_TOKEN=${API_TOKEN}\n      - SECRET_KEY=\n"
        )
        assert r.check_docker_compose(text) == []

    def test_comments_are_ignored(self):
        assert r.check_docker_compose("# privileged: true\n") == []
