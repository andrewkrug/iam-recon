use std::io::Write;

use crate::model::graph::Graph;
use crate::querying::presets::privesc;

/// Write a standard graph visualization in DOT format
pub fn write_standard_dot(
    graph: &Graph,
    w: &mut dyn Write,
    with_services: bool,
) -> std::io::Result<()> {
    writeln!(w, "digraph iam_recon {{")?;
    writeln!(w, "  rankdir=LR;")?;
    writeln!(w, "  node [shape=ellipse];")?;
    writeln!(w)?;

    // Nodes
    for node in &graph.nodes {
        let name = node.searchable_name().replace('/', "_").replace('.', "_");
        let label = node.searchable_name();

        let (color, shape) = if node.is_admin {
            ("lightblue", if node.is_user() { "box" } else { "ellipse" })
        } else if privesc::can_privesc(graph, node)
            .map(|(can, _)| can)
            .unwrap_or(false)
        {
            ("lightcoral", if node.is_user() { "box" } else { "ellipse" })
        } else {
            ("white", if node.is_user() { "box" } else { "ellipse" })
        };

        writeln!(
            w,
            "  {} [label=\"{}\", style=filled, fillcolor=\"{}\", shape={}];",
            name, label, color, shape
        )?;
    }

    writeln!(w)?;

    // Edges
    for edge in &graph.edges {
        let src = edge
            .source
            .split(':')
            .last()
            .unwrap_or(&edge.source)
            .replace('/', "_")
            .replace('.', "_");
        let dst = edge
            .destination
            .split(':')
            .last()
            .unwrap_or(&edge.destination)
            .replace('/', "_")
            .replace('.', "_");
        writeln!(w, "  {} -> {} [label=\"{}\"];", src, dst, edge.short_reason)?;
    }

    if with_services {
        writeln!(w)?;
        writeln!(w, "  // Service nodes")?;

        let service_map =
            crate::querying::presets::serviceaccess::compose_service_access_map(graph);
        for (service, roles) in &service_map {
            let svc_name = service.replace('.', "_");
            writeln!(
                w,
                "  {} [label=\"{}\", shape=diamond, style=filled, fillcolor=lightyellow];",
                svc_name, service
            )?;
            for role in roles {
                let role_name = role.searchable_name().replace('/', "_").replace('.', "_");
                writeln!(w, "  {} -> {} [style=dashed];", svc_name, role_name)?;
            }
        }
    }

    writeln!(w, "}}")?;
    Ok(())
}

/// Write privilege escalation-only DOT graph
pub fn write_privesc_dot(graph: &Graph, w: &mut dyn Write) -> std::io::Result<()> {
    writeln!(w, "digraph iam_recon_privesc {{")?;
    writeln!(w, "  rankdir=LR;")?;
    writeln!(w)?;

    // Only include admin nodes and nodes that can privesc
    let mut relevant_nodes = std::collections::HashSet::new();
    let mut relevant_edges = Vec::new();

    for node in &graph.nodes {
        if node.is_admin {
            relevant_nodes.insert(node.arn.clone());
        } else if let Some((can, path)) = privesc::can_privesc(graph, node) {
            if can {
                relevant_nodes.insert(node.arn.clone());
                for edge in &path {
                    relevant_nodes.insert(edge.destination.clone());
                    relevant_edges.push(edge.clone());
                }
            }
        }
    }

    for node in &graph.nodes {
        if !relevant_nodes.contains(&node.arn) {
            continue;
        }
        let name = node.searchable_name().replace('/', "_").replace('.', "_");
        let label = node.searchable_name();
        let color = if node.is_admin {
            "lightblue"
        } else {
            "lightcoral"
        };
        let shape = if node.is_user() { "box" } else { "ellipse" };
        writeln!(
            w,
            "  {} [label=\"{}\", style=filled, fillcolor=\"{}\", shape={}];",
            name, label, color, shape
        )?;
    }

    writeln!(w)?;

    for edge in &relevant_edges {
        let src = edge
            .source
            .split(':')
            .last()
            .unwrap_or(&edge.source)
            .replace('/', "_")
            .replace('.', "_");
        let dst = edge
            .destination
            .split(':')
            .last()
            .unwrap_or(&edge.destination)
            .replace('/', "_")
            .replace('.', "_");
        writeln!(w, "  {} -> {} [label=\"{}\"];", src, dst, edge.short_reason)?;
    }

    writeln!(w, "}}")?;
    Ok(())
}

/// Render DOT to SVG/PNG by shelling out to Graphviz `dot` command.
/// Requires Graphviz to be installed (`brew install graphviz` / `apt install graphviz`).
pub fn render_dot(dot_content: &str, output_path: &str, format: &str) -> std::io::Result<()> {
    let mut child = match std::process::Command::new("dot")
        .arg(format!("-T{}", format))
        .arg("-o")
        .arg(output_path)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Graphviz 'dot' command not found. Install it with:\n  \
                 macOS:  brew install graphviz\n  \
                 Debian: sudo apt install graphviz\n  \
                 Or use --format dot to get the raw DOT file.",
            ));
        }
        Err(e) => return Err(e),
    };

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(dot_content.as_bytes())?;
    }
    // Close stdin so dot can process
    drop(child.stdin.take());

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "dot command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }

    Ok(())
}
