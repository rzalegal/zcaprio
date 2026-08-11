use std::{path::Path, process::Command};

use serde_json::{Value, json};

#[test]
fn distributes_one_library_package_without_executable_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is nested in the workspace");
    let output = Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .expect("Cargo metadata is available");
    assert!(output.status.success(), "Cargo metadata failed");

    let metadata: Value = serde_json::from_slice(&output.stdout).expect("metadata is JSON");
    let members = metadata["workspace_members"]
        .as_array()
        .expect("workspace members are present");

    assert_eq!(members.len(), 1, "the workspace must be library-only");

    let package = metadata["packages"]
        .as_array()
        .expect("workspace packages are present")
        .iter()
        .find(|package| package["id"] == members[0])
        .expect("the sole member has package metadata");

    assert_eq!(package["name"], "zcaprio");
    let targets = package["targets"]
        .as_array()
        .expect("package targets are present");
    assert!(
        targets
            .iter()
            .any(|target| target["kind"] == json!(["lib"]))
    );
    assert!(
        targets
            .iter()
            .all(|target| target["kind"] != json!(["bin"]))
    );
}
