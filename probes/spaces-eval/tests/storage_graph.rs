// SPDX-License-Identifier: MPL-2.0

//! R25, "Muniment storage without SQLite": what the dependency graph says.
//!
//! `spaces_side.rs` runs the whole `Manager` over a map store with no SQLite at
//! runtime. This file records the other half: the fork's feature wiring still
//! links sqlx whenever the spaces traits are enabled.

type Graph = std::collections::BTreeMap<(String, String), Vec<String>>;

/// Cargo.lock as {(name, version): dependency strings}.
fn lock() -> Graph {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock")).unwrap();
    let mut graph = Graph::new();
    for block in text.split("[[package]]").skip(1) {
        let field = |key: &str| {
            block
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .map(|rest| {
                    rest.trim_matches(|c| c == ' ' || c == '=' || c == '"')
                        .to_string()
                })
        };
        let (name, version) = (field("name").unwrap(), field("version").unwrap());
        let dependencies = block
            .lines()
            .skip_while(|line| !line.starts_with("dependencies"))
            .skip(1)
            .take_while(|line| line.starts_with(' '))
            .map(|line| {
                line.trim()
                    .trim_matches(|c| c == '"' || c == ',')
                    .to_string()
            })
            .collect();
        graph.insert((name, version), dependencies);
    }
    graph
}

/// The locked entries of `name` (one per version).
fn entries<'a>(graph: &'a Graph, name: &str) -> Vec<(&'a (String, String), &'a Vec<String>)> {
    graph.iter().filter(|((n, _), _)| n == name).collect()
}

/// Whether the package `name` at `version` (any version when `None`) reaches `target`.
fn reaches(graph: &Graph, name: &str, version: Option<&str>, target: &str) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    let mut stack: Vec<(String, String)> = entries(graph, name)
        .into_iter()
        .filter(|((_, v), _)| version.is_none_or(|wanted| v == wanted))
        .map(|(key, _)| key.clone())
        .collect();
    while let Some(key) = stack.pop() {
        if !seen.insert(key.clone()) {
            continue;
        }
        for dep in &graph[&key] {
            let mut parts = dep.split(' ');
            let dep_name = parts.next().unwrap();
            if dep_name == target {
                return true;
            }
            match parts.next() {
                Some(dep_version) => stack.push((dep_name.to_string(), dep_version.to_string())),
                None => stack.extend(entries(graph, dep_name).into_iter().map(|(k, _)| k.clone())),
            }
        }
    }
    false
}

/// The store traits `Manager` is bounded by live behind p2mere-store's `spaces`
/// feature, which depends on `sqlite`; the crate therefore links sqlx even for
/// a backend that never opens SQLite. Verdict input: partial. The coupling is a
/// feature-graph fault in the fork, not an API one (the map store above proves
/// the traits are backend-neutral).
#[test]
fn c6_spaces_store_traits_still_link_sqlx() {
    let graph = lock();
    assert!(reaches(&graph, "p2mere-store", Some("0.9.0"), "sqlx"));
    assert!(reaches(&graph, "p2mere-spaces", Some("0.9.0"), "sqlx"));
}

/// The family's group code carries no SQLite: Stickleback's group session and lane
/// run on Muniment and p2mere-encryption alone.
#[test]
fn c6_stickleback_group_code_does_not_link_sqlx() {
    let graph = lock();
    assert!(!reaches(&graph, "stickleback", None, "sqlx"));
    assert!(!reaches(&graph, "muniment", None, "sqlx"));
}
