use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_axiom"))
}

#[test]
fn test_cli_version() {
    let output = cli().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("axiom"));
}

#[test]
fn test_cli_help() {
    let output = cli().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage") || stdout.contains("Commands"));
}

#[test]
fn test_cli_generate_verify() {
    let dir = tempfile::TempDir::new().unwrap();
    let axm_path = dir.path().join("test.axm");
    let out = cli().arg("generate").arg(&axm_path).output().unwrap();
    assert!(out.status.success(), "generate failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(axm_path.exists(), "generated file not found");

    let out = cli().arg("verify").arg(&axm_path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() || stdout.contains("PASS"), "verify failed: {}", stdout);
}

#[test]
fn test_cli_key_generate() {
    let dir = tempfile::TempDir::new().unwrap();
    let key_path = dir.path().join("test.key");
    let out = cli()
        .args(["key", "generate", &key_path.to_string_lossy()])
        .output()
        .unwrap();
    assert!(out.status.success(), "key generate failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(key_path.exists(), "key file not found");
}
