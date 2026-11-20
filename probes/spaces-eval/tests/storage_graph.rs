// SPDX-License-Identifier: MPL-2.0

//! The map-backed store and the family group code both support builds without
//! SQLite. Check the features Cargo actually enables for the standalone probe.

#[test]
fn c6_map_store_and_family_group_code_build_without_sqlite() {
    let output = std::process::Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "tree",
            "--locked",
            "--offline",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "-p",
            "spaces-eval",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8(output.stdout).unwrap();
    for package in ["p2mere-spaces", "p2mere-store", "stickleback", "muniment"] {
        assert!(
            tree.lines()
                .any(|line| line.split_whitespace().next() == Some(package)),
            "missing {package} from the dependency tree"
        );
    }
    assert!(
        !tree.lines().any(|line| line.starts_with("sqlx v")),
        "{tree}"
    );
}
