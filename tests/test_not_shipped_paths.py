"""#40 precision: inline Rust test modules, CI/release infra scripts and one-time
installer scripts are not the shipped surface (block/goose, screenpipe/screenpipe)."""
from __future__ import annotations

from src.scanner.rust_tests import mask_rust, rust_test_lines
from src.scanner.scan import (
    _NONSHIPPED_FINDING_WEIGHT,
    _finding_grade_weight,
    _finding_is_blocking,
    _is_installer_script,
    _is_unshipped_script,
    _scan_content,
    finding_is_shipped,
)

# A real-looking PEM body (the scanner wants a key body, not just the header).
_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzmc7SPaB07+gK\n"
    "p/VETtmayzNASEaaGIEKO5eOrlrKfIMdmSyB38Ia4dCyxb8WKAROeBtaev8AXfKh\n"
    "-----END PRIVATE KEY-----"
)


def _hits(content: str, path: str, category: str) -> list:
    findings, _, _ = _scan_content(content, path)
    return [f for f in findings if f.category == category]


# ---------------------------------------------------------------- Rust test extents

def _goose_like(attr: str = "#[cfg(all(test, feature = \"native-tls\"))]") -> str:
    """Modeled on block/goose crates/goose-providers/src/api_client.rs: shipped code,
    then a feature-gated test module holding PEM fixtures in a `"\\` string."""
    return (
        "pub fn convert_key_to_pkcs8_pem(pem: &str) -> Result<String> {\n"
        "    if pem.starts_with('{') { return Err(anyhow!(\"}\")); }\n"
        "    Ok(pem.to_string())\n"
        "}\n"
        "\n"
        f"{attr}\n"
        "mod native_tls_tests {\n"
        "    use super::convert_key_to_pkcs8_pem;\n"
        "    const PKCS8_RSA_KEY: &str = \"\\\n" + _PEM + "\";\n"
        "    #[test]\n"
        "    fn converts() { assert!(convert_key_to_pkcs8_pem(PKCS8_RSA_KEY).is_ok()); }\n"
        "}\n"
    )


def test_rust_cfg_all_test_module_is_test_code():
    src = _goose_like()
    secrets = _hits(src, "crates/goose-providers/src/api_client.rs", "secret")
    keys = [f for f in secrets if f.name == "Private Key block"]
    assert keys, secrets
    for f in keys:
        assert f.test_code is True
        assert f.severity == "medium"
        assert not finding_is_shipped(f)
        assert not _finding_is_blocking(f)
        assert _finding_grade_weight(f) == _NONSHIPPED_FINDING_WEIGHT


def test_rust_cfg_test_and_test_fn_attrs():
    for attr in ("#[cfg(test)]", "#[cfg( test )]"):
        src = _goose_like(attr)
        keys = [f for f in _hits(src, "src/lib.rs", "secret") if f.name == "Private Key block"]
        assert keys and all(f.test_code for f in keys)
    src = (
        "pub fn real() {}\n"
        "#[tokio::test(flavor = \"multi_thread\")]\n"
        "async fn fixture() {\n"
        "    let k = \"\\\n" + _PEM + "\";\n"
        "}\n"
    )
    keys = [f for f in _hits(src, "src/lib.rs", "secret") if f.name == "Private Key block"]
    assert keys and all(f.test_code for f in keys)


def test_same_key_in_shipped_rust_code_still_blocks():
    src = "pub const KEY: &str = \"\\\n" + _PEM + "\";\n"
    keys = [f for f in _hits(src, "src/lib.rs", "secret") if f.name == "Private Key block"]
    assert keys
    assert keys[0].test_code is False
    assert keys[0].severity == "critical"
    assert _finding_is_blocking(keys[0])


def test_cfg_any_test_is_not_test_only():
    src = _goose_like("#[cfg(any(test, feature = \"fixtures\"))]")
    keys = [f for f in _hits(src, "src/lib.rs", "secret") if f.name == "Private Key block"]
    assert keys and not any(f.test_code for f in keys)


def test_rust_extent_ignores_braces_in_strings_chars_comments():
    src = (
        "#[cfg(test)]\n"            # 0
        "mod tests {\n"             # 1
        "    // a stray } in a comment\n"
        "    /* nested /* } */ } */\n"
        "    const A: &str = \"}}}\";\n"
        "    const B: &str = r#\"}\"# ;\n"
        "    const C: char = '}';\n"
        "    fn f<'a>(x: &'a str) -> &'a str { x }\n"
        "}\n"                       # 8
        "pub fn shipped() {}\n"     # 9
    )
    lines = rust_test_lines(src)
    assert lines == set(range(0, 9))
    assert 9 not in lines


def test_rust_out_of_line_module_and_use_are_one_line():
    src = "#[cfg(test)]\nmod tests;\npub fn shipped() { let x = 1; }\n"
    assert rust_test_lines(src) == {0, 1}


def test_rust_inner_cfg_test_marks_whole_file():
    src = "#![cfg(test)]\nfn a() {}\nfn b() {}\n"
    assert rust_test_lines(src) == {0, 1, 2, 3}


def test_rust_unbalanced_fails_closed():
    assert rust_test_lines("#[cfg(test)]\nmod tests {\n  fn a() {\n") == set()
    assert mask_rust("let s = \"never closed;\n") is None
    assert rust_test_lines("let s = \"never closed;\n#[cfg(test)] mod t { }\n") == set()


# ---------------------------------------------------------------- infra / release

def test_infra_runner_bootstrap_is_not_shipped():
    """Modeled on screenpipe infra/release-linux-runner/bootstrap.sh."""
    src = (
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -\n"
        "curl -fsSL https://bun.sh/install | BUN_INSTALL=/opt/bun bash -s -- bun-v1.3.10\n"
    )
    for path in ("infra/release-linux-runner/bootstrap.sh",
                 "infra/release-mac-runner/template.yml",
                 "ci/setup.sh", ".github/scripts/bootstrap.sh",
                 "scripts/release.sh", "scripts/release/notarize.sh"):
        hits = _hits(src, path, "dynamic_remote_load")
        assert hits, path
        for f in hits:
            assert f.severity == "medium", (path, f.severity)
            assert not finding_is_shipped(f), path
            assert not _finding_is_blocking(f), path


def test_importable_source_under_infra_still_counts():
    """The infra rule covers script/config files only: an author can't park importable
    code under infra/ to dodge the floor."""
    assert not _is_unshipped_script("infra/loader.py")
    assert not _is_unshipped_script("infra/runtime/index.js")
    assert _is_unshipped_script("infra/terraform/main.tf")


def test_other_scripts_still_block():
    src = "curl -fsSL https://example.org/x.sh | sh\n"
    for path in ("scripts/setup_dev.sh", "bin/run.sh", "src/start.sh"):
        hits = _hits(src, path, "dynamic_remote_load")
        assert hits and hits[0].severity == "critical", path
        assert _finding_is_blocking(hits[0]), path


# ---------------------------------------------------------------- installer scripts

def test_installer_script_curl_pipe_is_a_capability():
    """Modeled on block/goose download_cli.sh (run once by the user to install)."""
    src = "#!/bin/bash\ncurl -fsSL https://github.com/block/goose/releases/x.sh | bash\n"
    for path in ("download_cli.sh", "install.sh", "scripts/install.sh", "get-goose.sh",
                 "install-cli.ps1"):
        hits = _hits(src, path, "dynamic_remote_load")
        assert hits, path
        f = hits[0]
        assert f.kind == "capability" and f.severity == "low", path
        assert f.capability == "install:remote_script"
        assert not _finding_is_blocking(f)


def test_installer_rule_is_path_scoped():
    assert _is_installer_script("install.sh")
    assert _is_installer_script("scripts/download-cli.sh")
    assert not _is_installer_script("src/install.sh")
    assert not _is_installer_script("packages/cli/install.sh")
    assert not _is_installer_script("install.py")
    assert not _is_installer_script("uninstall.sh")


# ---------------------------------------------------------------- real runtime stays

def test_build_rs_and_action_yml_still_block():
    """build.rs runs on the user's `cargo build`; action.yml steps run on the user's
    runner. Both are shipped runtime and keep their critical."""
    rs = ("fn main() {\n    Command::new(\"sh\")\n"
          "        .args([\"-c\", \"curl -fsSL https://bun.sh/install | bash\"])\n"
          "        .output();\n}\n")
    hits = _hits(rs, "crates/screenpipe-audio/build.rs", "dynamic_remote_load")
    assert hits and hits[0].severity == "critical" and _finding_is_blocking(hits[0])
    yml = ("runs:\n  using: composite\n  steps:\n    - run: |\n"
           "        curl -fsSL https://claude.ai/install.sh | bash\n")
    hits = _hits(yml, "base-action/action.yml", "dynamic_remote_load")
    assert hits and hits[0].severity == "critical" and _finding_is_blocking(hits[0])
