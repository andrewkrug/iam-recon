pub mod risk;
pub mod server;

use crate::model::graph::Graph;
use crate::querying::presets::privesc;

/// Convert a Graph into vis.js nodes/edges format (pathfinding.cloud style)
pub fn graph_to_visjs_json(graph: &Graph) -> serde_json::Value {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Assign hierarchical levels: admins at bottom, users at top, roles in between
    for node in graph.nodes.iter() {
        let can_esc = privesc::can_privesc(graph, node)
            .map(|(can, _)| can)
            .unwrap_or(false);

        let (bg, border, node_type) = if node.is_admin {
            ("#ff9999", "#b36b6b", "admin")
        } else if can_esc {
            ("#ffcc99", "#b38f6b", "privesc")
        } else if node.is_user() {
            ("#99ccff", "#6b8fb3", "user")
        } else {
            ("#d5eaf5", "#95a8b8", "role")
        };

        nodes.push(serde_json::json!({
            "id": node.arn,
            "label": node.searchable_name(),
            "color": {
                "background": bg,
                "border": border,
                "highlight": { "background": bg, "border": "#ff9900" },
                "hover": { "background": bg, "border": "#ff9900" }
            },
            "shape": "box",
            "font": { "size": 14, "face": "Arial", "color": "#232f3e", "bold": { "color": "#232f3e" } },
            "borderWidth": 2,
            "shadow": { "enabled": true, "color": "rgba(0,0,0,0.15)", "size": 6, "x": 2, "y": 2 },
            "margin": { "top": 10, "bottom": 10, "left": 14, "right": 14 },
            "widthConstraint": { "minimum": 140, "maximum": 260 },
            // Custom data for the detail panel
            "node_type": node_type,
            "is_admin": node.is_admin,
            "can_privesc": can_esc,
            "has_mfa": node.has_mfa,
            "access_keys": node.access_keys,
            "active_password": node.active_password,
            "tags": node.tags,
            "policies": build_policy_entries(&node.attached_policies),
            "trust_policy": node.trust_policy.as_ref().map(|doc| serde_json::json!({
                "name": format!("{}-trust", node.searchable_name()),
                "document": doc,
                "risks": risk::analyze_policy(doc),
            })),
            "arn": node.arn,
        }));
    }

    for (i, edge) in graph.edges.iter().enumerate() {
        edges.push(serde_json::json!({
            "id": format!("e{}", i),
            "from": edge.source,
            "to": edge.destination,
            "label": edge.short_reason,
            "arrows": { "to": { "enabled": true, "scaleFactor": 1.0, "type": "arrow" } },
            "color": { "color": "#666", "highlight": "#ff9900", "hover": "#ff9900", "opacity": 0.85 },
            "width": 2,
            "font": {
                "size": 11, "face": "Arial", "color": "#ddd",
                "strokeWidth": 0, "background": "rgba(20,20,30,0.85)",
                "align": "middle"
            },
            "smooth": { "type": "curvedCW", "roundness": 0.15 },
            "reason": edge.reason,
            "short_reason": edge.short_reason,
        }));
    }

    serde_json::json!({
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "account_id": graph.metadata.account_id,
            "node_count": graph.nodes.len(),
            "edge_count": graph.edges.len(),
            "admin_count": graph.nodes.iter().filter(|n| n.is_admin).count(),
        }
    })
}

/// Build per-policy JSON entries with full documents and risk analysis,
/// for embedding directly in the web UI.
fn build_policy_entries(
    policies: &[std::sync::Arc<crate::model::policy::Policy>],
) -> Vec<serde_json::Value> {
    policies
        .iter()
        .map(|p| {
            let risks = risk::analyze_policy(&p.policy_doc);
            serde_json::json!({
                "name": p.name,
                "arn": p.arn,
                "document": p.policy_doc,
                "risks": risks,
            })
        })
        .collect()
}

/// The embedded HTML — pathfinding.cloud visual style using vis.js
pub const INTERACTIVE_HTML: &str = r##"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>IAM Recon — Attack Graph</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
:root {
  --bg: #0B0B0F; --card: #1A1A24; --text: #E4E4E8; --dim: #70708a;
  --border: #2B2B3A; --accent: #632CA6; --pink: #D82D7E; --hi: #ff9900;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background:var(--bg); color:var(--text); }
#app { display:flex; height:100vh; }

/* Graph area */
#graph-wrap { flex:1; position:relative; margin:8px; }
#graph-container { width:100%; height:100%; background:var(--card); border:1px solid var(--border); border-radius:8px; }

/* Zoom buttons */
.zoom-btn { position:absolute; right:16px; width:34px; height:34px; border-radius:6px;
  border:1px solid var(--border); background:var(--card); color:var(--text); font-size:18px;
  cursor:pointer; display:flex; align-items:center; justify-content:center; z-index:5; transition:all .15s; }
.zoom-btn:hover { background:var(--accent); color:#fff; }
#zin { bottom:100px; } #zout { bottom:60px; } #zfit { bottom:20px; }

/* Sidebar */
#sidebar { width:370px; background:var(--card); border-left:1px solid var(--border);
  display:flex; flex-direction:column; overflow:hidden; }

#hdr { padding:14px 18px; background:linear-gradient(135deg, var(--accent), var(--pink));
  border-bottom:1px solid var(--border); }
#hdr h1 { font-size:15px; font-weight:700; color:#fff; letter-spacing:.5px; }
#hdr .sub { font-size:11px; color:rgba(255,255,255,.65); margin-top:3px; }

#stats-bar { display:flex; gap:14px; padding:10px 18px; border-bottom:1px solid var(--border); font-size:12px; }
.st { display:flex; align-items:center; gap:5px; }
.st-dot { width:9px; height:9px; border-radius:2px; }
.st b { color:var(--text); } .st span { color:var(--dim); }

#search-wrap { padding:10px 18px; border-bottom:1px solid var(--border); }
#search { width:100%; padding:7px 11px; background:var(--bg); border:1px solid var(--border);
  color:var(--text); border-radius:5px; font-size:13px; outline:none; }
#search:focus { border-color:var(--accent); }

#legend { padding:10px 18px; border-bottom:1px solid var(--border); }
#legend h4 { font-size:10px; text-transform:uppercase; letter-spacing:1px; color:var(--dim); margin-bottom:6px; }
.lg { display:flex; flex-wrap:wrap; gap:8px; }
.li { display:flex; align-items:center; gap:4px; font-size:11px; color:var(--dim); }
.lb { width:16px; height:16px; border-radius:3px; border:1px solid rgba(0,0,0,.15); }

#btns { padding:10px 18px; border-bottom:1px solid var(--border); display:flex; flex-wrap:wrap; gap:5px; }
#btns button { background:var(--bg); border:1px solid var(--border); color:var(--dim);
  padding:5px 10px; border-radius:5px; font-size:11px; cursor:pointer; transition:all .15s; }
#btns button:hover { background:var(--accent); color:#fff; border-color:var(--accent); }
#btns button.on { background:var(--accent); color:#fff; border-color:var(--accent); }

#detail { flex:1; padding:14px 18px; overflow-y:auto; font-size:13px; line-height:1.55; }
#detail h3 { font-size:13px; font-weight:700; padding:7px 11px; background:var(--accent);
  border-radius:5px; margin-bottom:10px; color:#fff; }
.p { margin:5px 0; } .pk { font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:var(--dim); }
.pv { color:var(--text); margin-top:1px; }
.pv.mono { font-family:'Courier New',monospace; font-size:11px; word-break:break-all; }
.tag { display:inline-block; background:var(--bg); border:1px solid var(--border); border-radius:3px;
  padding:1px 7px; font-size:10px; margin:2px; color:var(--dim); }
.tag.red { border-color:#ff9999; color:#ff9999; }
.tag.orange { border-color:#ffcc99; color:#ffcc99; }
.tag.green { border-color:#99ff99; color:#99ff99; }

.vis-tooltip { background:var(--card)!important; color:var(--text)!important;
  border:2px solid var(--accent)!important; border-radius:6px!important;
  padding:10px!important; font-size:12px!important; max-width:400px!important; }

/* Policy row in sidebar */
.policy-row { display:flex; align-items:center; justify-content:space-between;
  padding:6px 10px; margin:3px 0; background:var(--bg); border:1px solid var(--border);
  border-radius:5px; cursor:pointer; font-size:12px; transition:all .15s; }
.policy-row:hover { border-color:var(--accent); background:rgba(99,44,166,0.1); }
.policy-name { color:var(--text); font-weight:500; flex:1; overflow:hidden; text-overflow:ellipsis; }
.policy-kind { color:var(--dim); font-size:10px; text-transform:uppercase; margin:0 6px; }
.risk-badge { font-size:10px; font-weight:700; padding:2px 6px; border-radius:3px; text-transform:uppercase; }
.risk-badge.risk-low { background:#3b82f6; color:#fff; }
.risk-badge.risk-medium { background:#f59e0b; color:#000; }
.risk-badge.risk-high { background:#ef4444; color:#fff; }
.risk-badge.risk-critical { background:#991b1b; color:#fff; border:1px solid #fca5a5; }

/* Policy modal overlay */
#policy-modal { display:none; position:fixed; top:0; left:0; right:0; bottom:0;
  background:rgba(0,0,0,0.8); z-index:100; align-items:center; justify-content:center; }
.pm-card { background:var(--card); border:2px solid var(--accent); border-radius:10px;
  width:90%; max-width:1100px; height:85vh; display:flex; flex-direction:column;
  box-shadow:0 20px 60px rgba(0,0,0,0.6); }
.pm-header { padding:14px 20px; background:linear-gradient(135deg,var(--accent),var(--pink));
  color:#fff; font-size:15px; font-weight:700; display:flex; justify-content:space-between;
  align-items:center; border-radius:8px 8px 0 0; }
.pm-close { background:rgba(255,255,255,0.2); border:none; color:#fff; width:30px; height:30px;
  border-radius:50%; font-size:18px; cursor:pointer; font-weight:700; }
.pm-close:hover { background:rgba(255,255,255,0.35); }
.pm-content { flex:1; display:flex; overflow:hidden; }
.pm-risks { width:320px; padding:14px 18px; overflow-y:auto; border-right:1px solid var(--border); font-size:12px; }
.pm-risks h4 { font-size:11px; text-transform:uppercase; color:var(--dim); letter-spacing:1px; margin-bottom:8px; }
.pm-risks ul { list-style:none; }
.pm-risks li { padding:8px; margin:4px 0; background:var(--bg); border-left:3px solid var(--dim); border-radius:3px; }
.pm-risks li.risk-low { border-left-color:#3b82f6; }
.pm-risks li.risk-medium { border-left-color:#f59e0b; }
.pm-risks li.risk-high { border-left-color:#ef4444; }
.pm-risks li.risk-critical { border-left-color:#991b1b; background:rgba(153,27,27,0.15); }
.pm-risks li code { background:rgba(0,0,0,0.3); padding:1px 5px; border-radius:3px; color:#ffcc99; font-size:11px; }
.pm-risks li span { color:var(--dim); display:block; margin-top:4px; }
.pm-body { flex:1; padding:14px 18px; overflow:auto; font-family:'Courier New',monospace; font-size:12px;
  background:#0a0a12; }

/* JSON syntax highlighting */
.json-doc { color:#cbd5e1; line-height:1.5; white-space:pre; }
.j-k { color:#93c5fd; }     /* keys */
.j-s { color:#86efac; }     /* strings */
.j-n { color:#fbbf24; }     /* numbers */
.j-b { color:#c084fc; }     /* booleans */
.j-nl { color:#94a3b8; }    /* null */
.j-p { color:#64748b; }     /* punctuation */

/* Dangerous statement highlighting */
.stmt-block { display:block; padding:8px 12px; margin:4px 0;
  border-left:3px solid transparent; border-radius:4px; }
.stmt-block.stmt-low { border-left-color:#3b82f6; background:rgba(59,130,246,0.08); }
.stmt-block.stmt-medium { border-left-color:#f59e0b; background:rgba(245,158,11,0.08); }
.stmt-block.stmt-high { border-left-color:#ef4444; background:rgba(239,68,68,0.1); }
.stmt-block.stmt-critical { border-left-color:#991b1b; background:rgba(153,27,27,0.18);
  box-shadow:inset 0 0 20px rgba(239,68,68,0.15); }
</style>
</head>
<body>
<div id="app">
  <div id="graph-wrap">
    <div id="graph-container"></div>
    <button class="zoom-btn" id="zin" onclick="zoomIn()">+</button>
    <button class="zoom-btn" id="zout" onclick="zoomOut()">−</button>
    <button class="zoom-btn" id="zfit" onclick="network.fit({animation:true})">⊡</button>
  </div>
  <div id="sidebar">
    <div id="hdr"><h1>IAM Recon</h1><div class="sub">Attack Surface Graph Explorer</div></div>
    <div id="stats-bar"></div>
    <div id="search-wrap"><input id="search" placeholder="Search principals... (Ctrl+F)"></div>
    <div id="legend">
      <h4>Node Types</h4>
      <div class="lg">
        <div class="li"><div class="lb" style="background:#ff9999"></div>Admin</div>
        <div class="li"><div class="lb" style="background:#ffcc99"></div>Privesc</div>
        <div class="li"><div class="lb" style="background:#99ccff"></div>User</div>
        <div class="li"><div class="lb" style="background:#d5eaf5"></div>Role</div>
      </div>
    </div>
    <div id="btns">
      <button class="on" onclick="setLayout('physics',this)">Force</button>
      <button onclick="setLayout('UD',this)">↓ Top-Down</button>
      <button onclick="setLayout('LR',this)">→ Left-Right</button>
      <button onclick="network.fit({animation:true})">Fit</button>
      <button onclick="filterAdmin()">Admins</button>
      <button onclick="filterPrivesc()">Privesc</button>
      <button onclick="resetFilter()">Reset</button>
    </div>
    <div id="detail"><p style="color:var(--dim)">Click a node or edge to inspect.</p></div>
  </div>
</div>

<!-- Policy JSON modal with iam-rs risk highlighting -->
<div id="policy-modal" onclick="if(event.target===this)closePolicy()">
  <div class="pm-card">
    <div class="pm-header">
      <span id="pm-title">Policy</span>
      <button class="pm-close" onclick="closePolicy()">×</button>
    </div>
    <div class="pm-content">
      <div class="pm-risks" id="pm-risks"></div>
      <div class="pm-body" id="pm-body"></div>
    </div>
  </div>
</div>

<script>
const D = window.__IAM_RECON_DATA__;

document.getElementById('stats-bar').innerHTML =
  `<div class="st"><div class="st-dot" style="background:#99ccff"></div><b>${D.metadata.node_count}</b><span>principals</span></div>`+
  `<div class="st"><div class="st-dot" style="background:#666"></div><b>${D.metadata.edge_count}</b><span>edges</span></div>`+
  `<div class="st"><div class="st-dot" style="background:#ff9999"></div><b>${D.metadata.admin_count}</b><span>admins</span></div>`;

const rawNodes = D.nodes, rawEdges = D.edges;
const nodes = new vis.DataSet(rawNodes);
const edges = new vis.DataSet(rawEdges);

const network = new vis.Network(document.getElementById('graph-container'), { nodes, edges }, {
  layout: { improvedLayout: true, randomSeed: 42 },
  physics: {
    enabled: true,
    solver: 'forceAtlas2Based',
    forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 160, springConstant: 0.04, damping: 0.4 },
    stabilization: { iterations: 300, fit: true, updateInterval: 25 },
    maxVelocity: 50, minVelocity: 0.75,
  },
  interaction: { hover: true, tooltipDelay: 200, dragNodes: true, dragView: true, zoomView: true, multiselect: true },
  edges: {
    arrows: { to: { enabled: true, scaleFactor: 1.0, type: 'arrow' } },
    color: { color: '#555', highlight: '#ff9900', hover: '#ff9900', opacity: 0.85 },
    width: 2,
    font: { size: 11, face: 'Arial', color: '#ccc', strokeWidth: 0, background: 'rgba(20,20,30,0.85)', align: 'middle' },
    smooth: { type: 'curvedCW', roundness: 0.15 },
    hoverWidth: 1.5, selectionWidth: 2,
  },
  nodes: {
    shape: 'box', borderWidth: 2,
    shadow: { enabled: true, color: 'rgba(0,0,0,0.15)', size: 6, x: 2, y: 2 },
    font: { size: 12, face: 'Arial', color: '#232f3e' },
    margin: { top: 6, bottom: 6, left: 10, right: 10 },
    widthConstraint: { minimum: 100, maximum: 220 },
    scaling: { label: { enabled: true, min: 8, max: 14 } },
  }
});

// Freeze physics after stabilization then fit view
network.once('stabilizationIterationsDone', function() {
  network.setOptions({ physics: { enabled: false } });
  network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
});

// Click
network.on('click', function(p) {
  const det = document.getElementById('detail');
  if (p.nodes.length) {
    const n = nodes.get(p.nodes[0]);
    let tags = '';
    if (n.is_admin) tags += '<span class="tag red">ADMIN</span>';
    if (n.can_privesc) tags += '<span class="tag orange">PRIVESC</span>';
    if (n.has_mfa) tags += '<span class="tag green">MFA</span>';

    // Build policy list with clickable View JSON buttons
    let policiesHtml = '';
    const allPolicies = [];
    if (n.policies && n.policies.length) {
      n.policies.forEach((pol, i) => allPolicies.push({...pol, _key: 'p'+i, _kind: 'identity'}));
    }
    if (n.trust_policy) {
      allPolicies.push({...n.trust_policy, _key: 'trust', _kind: 'trust'});
    }
    window.__currentPolicies = {};
    allPolicies.forEach(p => { window.__currentPolicies[p._key] = p; });

    if (allPolicies.length) {
      policiesHtml = '<div class="p"><div class="pk">Policies</div><div class="pv">';
      allPolicies.forEach(p => {
        const riskCount = (p.risks || []).length;
        const highestLevel = highestRiskLevel(p.risks || []);
        const riskBadge = riskCount > 0
          ? `<span class="risk-badge risk-${highestLevel}">${riskCount} risk${riskCount===1?'':'s'}</span>`
          : '';
        const kindLabel = p._kind === 'trust' ? 'trust' : 'identity';
        policiesHtml += `<div class="policy-row" onclick="showPolicy('${p._key}')">
          <span class="policy-name">${p.name}</span>
          <span class="policy-kind">${kindLabel}</span>
          ${riskBadge}
        </div>`;
      });
      policiesHtml += '</div></div>';
    }

    det.innerHTML =
      `<h3>${n.label}</h3>`+
      `<div class="p"><div class="pk">ARN</div><div class="pv mono">${n.arn}</div></div>`+
      `<div class="p"><div class="pk">Type</div><div class="pv">${n.node_type} ${tags}</div></div>`+
      `<div class="p"><div class="pk">Access Keys</div><div class="pv">${n.access_keys}</div></div>`+
      `<div class="p"><div class="pk">Password</div><div class="pv">${n.active_password}</div></div>`+
      policiesHtml+
      (n.tags&&Object.keys(n.tags).length ? `<div class="p"><div class="pk">Tags</div><div class="pv">${Object.entries(n.tags).map(([k,v])=>`<span class="tag">${k}=${v}</span>`).join('')}</div></div>` : '');
  } else if (p.edges.length) {
    const e = edges.get(p.edges[0]);
    det.innerHTML =
      `<h3>${e.short_reason}</h3>`+
      `<div class="p"><div class="pk">From</div><div class="pv mono">${e.from.split(':').pop()}</div></div>`+
      `<div class="p"><div class="pk">To</div><div class="pv mono">${e.to.split(':').pop()}</div></div>`+
      `<div class="p"><div class="pk">Reason</div><div class="pv">${e.reason}</div></div>`;
  }
});

function highestRiskLevel(risks) {
  const order = ['low', 'medium', 'high', 'critical'];
  let best = -1;
  risks.forEach(r => { const i = order.indexOf(r.level); if (i > best) best = i; });
  return best >= 0 ? order[best] : 'low';
}

// Show a policy in a modal with JSON + highlighted dangerous statements
function showPolicy(key) {
  const p = window.__currentPolicies[key];
  if (!p) return;

  const modal = document.getElementById('policy-modal');
  const title = document.getElementById('pm-title');
  const body = document.getElementById('pm-body');
  const risksPanel = document.getElementById('pm-risks');

  title.textContent = p.name;

  // Render risks summary at top
  if (p.risks && p.risks.length) {
    const grouped = {};
    p.risks.forEach(r => {
      if (!grouped[r.statement_index]) grouped[r.statement_index] = [];
      grouped[r.statement_index].push(r);
    });
    let html = '<h4>Risk Findings</h4><ul>';
    p.risks.forEach(r => {
      html += `<li class="risk-${r.level}"><b>[${r.level.toUpperCase()}]</b> <code>${r.rule}</code> — statement #${r.statement_index}${r.sid?' ('+r.sid+')':''}<br><span>${r.description}</span></li>`;
    });
    html += '</ul>';
    risksPanel.innerHTML = html;
    risksPanel.style.display = 'block';
  } else {
    risksPanel.innerHTML = '<div style="color:#66ff99">No risks detected by iam-rs analysis.</div>';
    risksPanel.style.display = 'block';
  }

  // Render JSON with highlighted dangerous statements
  body.innerHTML = renderPolicyJson(p.document, p.risks || []);
  modal.style.display = 'flex';
}

function closePolicy() { document.getElementById('policy-modal').style.display = 'none'; }

// Render policy JSON with statement-level highlighting
function renderPolicyJson(doc, risks) {
  // Map statement index -> highest risk level
  const stmtRisk = {};
  risks.forEach(r => {
    const cur = stmtRisk[r.statement_index];
    const order = ['low','medium','high','critical'];
    if (!cur || order.indexOf(r.level) > order.indexOf(cur)) {
      stmtRisk[r.statement_index] = r.level;
    }
  });

  // Render the top-level policy structure with per-statement wrappers
  let html = '<pre class="json-doc">';
  html += '<span class="j-p">{</span>\n';
  const keys = Object.keys(doc);
  keys.forEach((k, ki) => {
    if (k === 'Statement') {
      html += '  <span class="j-k">"Statement"</span>: <span class="j-p">[</span>\n';
      const stmts = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
      stmts.forEach((stmt, i) => {
        const lvl = stmtRisk[i];
        const cls = lvl ? ` stmt-${lvl}` : '';
        html += `    <div class="stmt-block${cls}" data-stmt="${i}">`;
        html += syntaxHighlight(JSON.stringify(stmt, null, 2).split('\n').map(l => '    ' + l).join('\n').trim());
        html += (i < stmts.length - 1 ? ',' : '');
        html += '</div>';
      });
      html += '  <span class="j-p">]</span>' + (ki < keys.length - 1 ? ',' : '') + '\n';
    } else {
      html += `  <span class="j-k">"${k}"</span>: ${syntaxHighlight(JSON.stringify(doc[k]))}${ki < keys.length - 1 ? ',' : ''}\n`;
    }
  });
  html += '<span class="j-p">}</span></pre>';
  return html;
}

function syntaxHighlight(json) {
  if (typeof json !== 'string') json = JSON.stringify(json, null, 2);
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function(match) {
    let cls = 'j-n';
    if (/^"/.test(match)) {
      cls = /:$/.test(match) ? 'j-k' : 'j-s';
    } else if (/true|false/.test(match)) {
      cls = 'j-b';
    } else if (/null/.test(match)) {
      cls = 'j-nl';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

// Hover: enlarge hovered node, push all others away, restore on blur
let savedPositions = null;
const PUSH_RADIUS = 400;   // pixels — nodes within this radius get pushed
const PUSH_STRENGTH = 80;  // how many pixels to push

network.on('hoverNode', function(params) {
  const hovId = params.node;
  const connectedEdges = network.getConnectedEdges(hovId);
  const neighborhood = new Set([hovId, ...network.getConnectedNodes(hovId)]);

  // Save all positions so we can restore on blur
  const allIds = rawNodes.map(n => n.id);
  savedPositions = network.getPositions(allIds);

  const hovPos = savedPositions[hovId];
  if (!hovPos) return;

  // Move every other node away from the hovered node
  allIds.forEach(nid => {
    if (nid === hovId) return;
    const pos = savedPositions[nid];
    if (!pos) return;
    const dx = pos.x - hovPos.x;
    const dy = pos.y - hovPos.y;
    const dist = Math.sqrt(dx*dx + dy*dy) || 1;
    if (dist < PUSH_RADIUS) {
      const push = PUSH_STRENGTH * (1 - dist / PUSH_RADIUS);
      network.moveNode(nid, pos.x + (dx/dist)*push, pos.y + (dy/dist)*push);
    }
  });

  // Style: enlarge hovered, dim non-connected
  const nu = [], eu = [];
  rawNodes.forEach(n => {
    if (n.id === hovId) {
      nu.push({ id: n.id, borderWidth: 4, font: { size: 16, color: '#232f3e' },
        shadow: { enabled: true, color: 'rgba(255,153,0,0.5)', size: 24, x: 0, y: 0 } });
    } else if (neighborhood.has(n.id)) {
      nu.push({ id: n.id, opacity: 1.0 });
    } else {
      nu.push({ id: n.id, opacity: 0.35 });
    }
  });
  rawEdges.forEach(e => {
    if (connectedEdges.includes(e.id)) {
      eu.push({ id: e.id, width: 3, color: { color: '#ff9900', opacity: 1 } });
    } else {
      eu.push({ id: e.id, color: { color: '#555', opacity: 0.1 } });
    }
  });
  nodes.update(nu);
  edges.update(eu);
});

network.on('blurNode', function() {
  // Restore positions
  if (savedPositions) {
    Object.entries(savedPositions).forEach(([nid, pos]) => {
      network.moveNode(nid, pos.x, pos.y);
    });
    savedPositions = null;
  }
  // Restore styles
  nodes.update(rawNodes.map(n => ({
    id: n.id, opacity: 1.0, borderWidth: 2,
    font: { size: 12, color: '#232f3e' },
    shadow: { enabled: true, color: 'rgba(0,0,0,0.15)', size: 6, x: 2, y: 2 }
  })));
  edges.update(rawEdges.map(e => ({
    id: e.id, width: 2, color: { color: '#555', highlight: '#ff9900', hover: '#ff9900', opacity: 0.85 }
  })));
});

// Search
document.getElementById('search').addEventListener('input', function() {
  const t = this.value.toLowerCase();
  if (!t) { nodes.update(rawNodes.map(n=>({id:n.id, hidden:false}))); return; }
  const hit = new Set();
  rawNodes.forEach(n => { if ((n.label||'').toLowerCase().includes(t) || (n.arn||'').toLowerCase().includes(t)) hit.add(n.id); });
  rawEdges.forEach(e => { if (hit.has(e.from)) hit.add(e.to); if (hit.has(e.to)) hit.add(e.from); });
  nodes.update(rawNodes.map(n=>({id:n.id, hidden:!hit.has(n.id)})));
});

// Layout
function setLayout(dir, btn) {
  if (dir === 'physics') {
    // Force-directed layout
    network.setOptions({
      layout: { hierarchical: { enabled: false } },
      physics: { enabled:true, solver:'forceAtlas2Based',
        forceAtlas2Based:{gravitationalConstant:-50,centralGravity:0.01,springLength:160,springConstant:0.04,damping:0.4},
        stabilization:{iterations:200,fit:true} }
    });
  } else {
    // Hierarchical in given direction
    network.setOptions({
      layout: { hierarchical: { enabled:true, direction:dir, sortMethod:'hubsize', nodeSpacing:180, levelSeparation:130 }},
      physics: { enabled:true, hierarchicalRepulsion:{nodeDistance:200,springLength:150}, stabilization:{iterations:100,fit:true} }
    });
  }
  network.once('stabilizationIterationsDone', ()=>{ network.setOptions({physics:{enabled:false}}); network.fit({animation:true}); });
  document.querySelectorAll('#btns button').forEach(b=>b.classList.remove('on'));
  if(btn) btn.classList.add('on');
}
function filterAdmin() { nodes.update(rawNodes.map(n=>({id:n.id, hidden:!n.is_admin}))); }
function filterPrivesc() {
  const ids = new Set();
  rawNodes.forEach(n=>{ if(n.is_admin||n.can_privesc) ids.add(n.id); });
  rawEdges.forEach(e=>{ if(ids.has(e.from)||ids.has(e.to)){ids.add(e.from);ids.add(e.to);} });
  nodes.update(rawNodes.map(n=>({id:n.id, hidden:!ids.has(n.id)})));
}
function resetFilter() { nodes.update(rawNodes.map(n=>({id:n.id, hidden:false}))); network.fit({animation:true}); }
function zoomIn() { network.moveTo({scale: network.getScale()*1.3, animation:{duration:200}}); }
function zoomOut() { network.moveTo({scale: network.getScale()/1.3, animation:{duration:200}}); }

// Keyboard
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    if (document.getElementById('policy-modal').style.display === 'flex') { closePolicy(); return; }
  }
  if (e.target.tagName === 'INPUT') return;
  if (e.key === 'f') network.fit({animation:true});
  if (e.key === 'r') resetFilter();
  if ((e.ctrlKey || e.metaKey) && e.key === 'f') { e.preventDefault(); document.getElementById('search').focus(); }
});
</script>
</body>
</html>"##;
