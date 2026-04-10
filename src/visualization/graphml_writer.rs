use std::io::Write;

use crate::model::graph::Graph;
use crate::querying::presets::privesc;

/// Write graph in GraphML format
pub fn write_standard_graphml(graph: &Graph, w: &mut dyn Write) -> std::io::Result<()> {
    writeln!(w, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writeln!(
        w,
        r#"<graphml xmlns="http://graphml.graphstruct.org/graphml">"#
    )?;

    // Key definitions
    writeln!(
        w,
        r#"  <key id="label" for="node" attr.name="label" attr.type="string"/>"#
    )?;
    writeln!(
        w,
        r#"  <key id="type" for="node" attr.name="type" attr.type="string"/>"#
    )?;
    writeln!(
        w,
        r#"  <key id="admin" for="node" attr.name="admin" attr.type="boolean"/>"#
    )?;
    writeln!(
        w,
        r#"  <key id="privesc" for="node" attr.name="privesc" attr.type="boolean"/>"#
    )?;
    writeln!(
        w,
        r#"  <key id="reason" for="edge" attr.name="reason" attr.type="string"/>"#
    )?;
    writeln!(
        w,
        r#"  <key id="short_reason" for="edge" attr.name="short_reason" attr.type="string"/>"#
    )?;

    writeln!(w, r#"  <graph id="G" edgedefault="directed">"#)?;

    // Nodes
    for node in &graph.nodes {
        let can_esc = privesc::can_privesc(graph, node)
            .map(|(can, _)| can)
            .unwrap_or(false);
        let node_type = if node.is_user() { "user" } else { "role" };

        writeln!(w, r#"    <node id="{}">"#, node.arn)?;
        writeln!(
            w,
            r#"      <data key="label">{}</data>"#,
            node.searchable_name()
        )?;
        writeln!(w, r#"      <data key="type">{}</data>"#, node_type)?;
        writeln!(w, r#"      <data key="admin">{}</data>"#, node.is_admin)?;
        writeln!(w, r#"      <data key="privesc">{}</data>"#, can_esc)?;
        writeln!(w, r#"    </node>"#)?;
    }

    // Edges
    for (i, edge) in graph.edges.iter().enumerate() {
        writeln!(
            w,
            r#"    <edge id="e{}" source="{}" target="{}">"#,
            i, edge.source, edge.destination
        )?;
        writeln!(
            w,
            r#"      <data key="reason">{}</data>"#,
            xml_escape(&edge.reason)
        )?;
        writeln!(
            w,
            r#"      <data key="short_reason">{}</data>"#,
            edge.short_reason
        )?;
        writeln!(w, r#"    </edge>"#)?;
    }

    writeln!(w, r#"  </graph>"#)?;
    writeln!(w, r#"</graphml>"#)?;

    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
