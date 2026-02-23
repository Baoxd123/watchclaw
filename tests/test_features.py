"""Tests for content feature extraction."""

import os

from watchclaw.features import extract_content_features, shannon_entropy


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_empty_bytes(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_single_byte(self):
        assert shannon_entropy(b"\x00\x00\x00\x00") == 0.0

    def test_two_chars_equal(self):
        # "ab" repeated → 1.0 bit
        e = shannon_entropy("abababab")
        assert abs(e - 1.0) < 0.01

    def test_two_bytes_equal(self):
        e = shannon_entropy(b"\x00\x01" * 4)
        assert abs(e - 1.0) < 0.01

    def test_high_entropy(self):
        import string
        data = string.ascii_letters + string.digits
        e = shannon_entropy(data)
        assert e > 4.0  # High entropy for diverse characters

    def test_high_entropy_random_bytes(self):
        # 256 distinct byte values → maximum entropy ≈ 8.0
        data = bytes(range(256))
        e = shannon_entropy(data)
        assert abs(e - 8.0) < 0.01

    def test_all_zeros_low_entropy(self):
        data = b"\x00" * 1000
        assert shannon_entropy(data) == 0.0

    def test_entropy_rounded_to_3_decimals(self):
        e = shannon_entropy("abc")
        # log2(3) ≈ 1.58496..., should round to 1.585
        assert e == round(e, 3)

    def test_bytes_vs_str_consistency(self):
        # ASCII-only: byte and string entropy should match
        text = "Hello, World!"
        assert shannon_entropy(text) == shannon_entropy(text.encode())


class TestExtractContentFeatures:
    def test_env_file_detection(self):
        content = "DATABASE_URL=postgres://localhost/db\nAPI_KEY=sk-1234567890abcdef12345\nSECRET=mysecret"
        features = extract_content_features(content, ".env")
        assert features["has_env_format"] is True
        assert features["file_type"] == "env"
        assert features["line_count"] == 3

    def test_api_key_detection(self):
        content = "api_key: sk-live-abcdefghijklmnopqrstuvwxyz1234"
        features = extract_content_features(content, "config.yaml")
        assert features["api_key_patterns"] >= 1

    def test_api_key_aws(self):
        content = "aws_key = AKIAIOSFODNN7EXAMPLE"
        features = extract_content_features(content)
        assert features["api_key_patterns"] >= 1

    def test_api_key_github_token(self):
        content = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        features = extract_content_features(content)
        assert features["api_key_patterns"] >= 1

    def test_api_key_slack_token(self):
        content = "SLACK_TOKEN=xoxb-1234567890-abcdefghij"
        features = extract_content_features(content)
        assert features["api_key_patterns"] >= 1

    def test_email_detection(self):
        content = "Contact: admin@example.com and user@test.org"
        features = extract_content_features(content)
        assert features["email_patterns"] == 2

    def test_ip_detection(self):
        content = "Server: 192.168.1.1\nBackup: 10.0.0.1"
        features = extract_content_features(content)
        assert features["ip_patterns"] == 2

    def test_url_detection(self):
        content = "Fetch from https://api.example.com/data and http://test.com"
        features = extract_content_features(content)
        assert features["url_patterns"] == 2

    def test_private_key_detection(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAK..."
        features = extract_content_features(content, "id_rsa")
        assert features["private_key_markers"] is True

    def test_private_key_ec(self):
        content = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQ..."
        features = extract_content_features(content)
        assert features["private_key_markers"] is True

    def test_private_key_generic(self):
        content = "-----BEGIN PRIVATE KEY-----\nMIIEvgI..."
        features = extract_content_features(content)
        assert features["private_key_markers"] is True

    def test_no_private_key_in_public_key(self):
        content = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg..."
        features = extract_content_features(content)
        assert features["private_key_markers"] is False

    def test_json_structure_detection(self):
        content = '{"key": "value", "nested": {"a": 1}}'
        features = extract_content_features(content, "data.json")
        assert features["has_json_structure"] is True

    def test_normal_python_file(self):
        content = 'def hello():\n    print("Hello, world!")\n\nhello()\n'
        features = extract_content_features(content, "main.py")
        assert features["file_type"] == "py"
        assert features["api_key_patterns"] == 0
        assert features["private_key_markers"] is False
        assert features["has_env_format"] is False

    def test_size_bytes(self):
        content = "Hello"
        features = extract_content_features(content)
        assert features["size_bytes"] == 5

    def test_bytes_input(self):
        content = b"Hello, bytes world!"
        features = extract_content_features(content)
        assert features["size_bytes"] == len(content)
        assert features["entropy"] > 0

    def test_bytes_input_with_api_key(self):
        content = b"token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        features = extract_content_features(content, "config.env")
        assert features["api_key_patterns"] >= 1

    def test_password_patterns(self):
        content = "password=hunter2\npasswd: secret123\npwd=abc"
        features = extract_content_features(content)
        assert features["password_patterns"] == 3

    def test_token_patterns(self):
        content = "token=abc123\nsecret: xyz\napi_key=foo"
        features = extract_content_features(content)
        assert features["token_patterns"] == 3

    def test_base64_blocks(self):
        content = "data: " + "A" * 50 + "=="
        features = extract_content_features(content)
        assert features["base64_blocks"] >= 1

    def test_shell_pipes(self):
        content = "cat file.txt | grep foo | sort | uniq"
        features = extract_content_features(content)
        assert features["shell_pipes"] == 3

    def test_eval_calls(self):
        content = 'eval("code")\nexec(compile("src", "f", "exec"))'
        features = extract_content_features(content)
        assert features["eval_calls"] == 3  # eval, exec, compile

    def test_multibyte_size_bytes(self):
        # Unicode characters take more bytes in UTF-8
        content = "Hello 世界"
        features = extract_content_features(content)
        assert features["size_bytes"] == len(content.encode("utf-8"))
        assert features["size_bytes"] > len(content)  # Multi-byte chars
