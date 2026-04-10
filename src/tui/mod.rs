//! Terminal UI — Westworld-meets-cyber aesthetic.
//!
//! Analysis and Attack Vector modules show a dashboard-style split view:
//! a scrollable finding list on top where you select items, and the
//! detail panel on the bottom showing the selected finding in full.
//! Press Enter to expand, Esc to go back, arrow keys to page through.

use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{prelude::*, widgets::*};

use crate::cli::completer::GraphCompleter;
use crate::model::graph::Graph;
use crate::util::storage;

// ─── Menu ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuItem {
    CreateGraph,
    GraphInfo,
    Query,
    Privesc,
    Analysis,
    Pathfinding,
    ServiceAccess,
    WrongAdmin,
}

impl MenuItem {
    fn all() -> &'static [MenuItem] {
        &[
            MenuItem::CreateGraph,
            MenuItem::GraphInfo,
            MenuItem::Query,
            MenuItem::Privesc,
            MenuItem::Analysis,
            MenuItem::Pathfinding,
            MenuItem::ServiceAccess,
            MenuItem::WrongAdmin,
        ]
    }
    fn label(&self) -> &'static str {
        match self {
            MenuItem::CreateGraph => "CREATE GRAPH",
            MenuItem::GraphInfo => "SYSTEM OVERVIEW",
            MenuItem::Query => "QUERY REPL",
            MenuItem::Privesc => "ESCALATION PATHS",
            MenuItem::Analysis => "THREAT ANALYSIS",
            MenuItem::Pathfinding => "ATTACK VECTORS",
            MenuItem::ServiceAccess => "SERVICE MAP",
            MenuItem::WrongAdmin => "ANOMALOUS ADMINS",
        }
    }
    fn icon(&self) -> &'static str {
        match self {
            MenuItem::CreateGraph => " ",
            MenuItem::GraphInfo => " ",
            MenuItem::Query => " ",
            MenuItem::Privesc => " ",
            MenuItem::Analysis => " ",
            MenuItem::Pathfinding => " ",
            MenuItem::ServiceAccess => " ",
            MenuItem::WrongAdmin => " ",
        }
    }
    fn has_detail_view(&self) -> bool {
        matches!(self, MenuItem::Analysis | MenuItem::Pathfinding)
    }
}

// ─── Styled helpers ─────────────────────────────────────────────

type SL = (String, Style);
fn s(t: &str) -> SL {
    (t.into(), Style::default().fg(Color::Gray))
}
fn h(t: &str) -> SL {
    (t.into(), Style::default().fg(Color::Cyan).bold())
}
fn d(t: &str) -> SL {
    (t.into(), Style::default().fg(Color::DarkGray))
}
fn r(t: &str) -> SL {
    (t.into(), Style::default().fg(Color::Red).bold())
}
fn g(t: &str) -> SL {
    (t.into(), Style::default().fg(Color::Green))
}
fn y(t: &str) -> SL {
    (t.into(), Style::default().fg(Color::Yellow))
}
fn w(t: &str) -> SL {
    (t.into(), Style::default().fg(Color::White).bold())
}
fn blank() -> SL {
    (String::new(), Style::default())
}
fn sl(t: &str, sty: Style) -> SL {
    (t.into(), sty)
}

// ─── Detail item for drill-down views ───────────────────────────

#[derive(Clone)]
struct DetailItem {
    /// One-line summary shown in the list
    summary: String,
    summary_style: Style,
    /// Full detail lines shown when selected
    detail: Vec<SL>,
}

// ─── Progress channel ───────────────────────────────────────────

enum ProgressMsg {
    Line(SL),
    /// A selectable finding item (for Analysis/Pathfinding)
    Item(DetailItem),
    /// A freshly created graph ready to replace the current one
    GraphReady(Box<Graph>),
    Done,
}

// ─── Cached view result ─────────────────────────────────────────

#[derive(Clone, Default)]
struct CachedView {
    output_lines: Vec<SL>,
    items: Vec<DetailItem>,
    summary_header: Vec<SL>,
}

// ─── Focus state ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    /// Menu sidebar — up/down changes module, Enter goes into content
    Menu,
    /// Content panel — up/down navigates findings, Esc returns to menu
    Content,
    /// Quit confirmation overlay
    QuitConfirm,
    /// Help overlay showing all keybindings
    Help,
}

// ─── App state ──────────────────────────────────────────────────

struct App {
    graph: Arc<Graph>,
    selected_menu: usize,
    focus: Focus,
    // Plain output lines (for non-detail views)
    output_lines: Vec<SL>,
    output_scroll: u16,
    // Detail items (for Analysis/Pathfinding)
    items: Vec<DetailItem>,
    selected_item: usize,
    detail_scroll: u16,
    // Shared state
    log_lines: Vec<String>,
    running: bool,
    tick: u64,
    processing: bool,
    progress_rx: Option<mpsc::Receiver<ProgressMsg>>,
    abort_flag: Arc<AtomicBool>,
    summary_header: Vec<SL>,
    view_cache: std::collections::HashMap<usize, CachedView>,
    // Query REPL state
    query_input: String,
    query_cursor: usize,
    query_hint: String,
    query_history: Vec<String>,
    completer: GraphCompleter,
    // Create Graph wizard state
    profiles: Vec<crate::util::aws_config::AwsProfile>,
    selected_profile: usize,
    creating_graph: bool,
}

impl App {
    fn new(graph: Graph) -> Self {
        let completer = GraphCompleter::from_graph(&graph);
        let graph = Arc::new(graph);
        let mut app = Self {
            graph,
            selected_menu: 0,
            focus: Focus::Menu,
            output_lines: vec![],
            output_scroll: 0,
            items: vec![],
            selected_item: 0,
            detail_scroll: 0,
            log_lines: vec!["IAM-RECON :: ONLINE".into(), "Graph loaded".into()],
            running: true,
            tick: 0,
            processing: false,
            progress_rx: None,
            abort_flag: Arc::new(AtomicBool::new(false)),
            summary_header: vec![],
            view_cache: std::collections::HashMap::new(),
            query_input: String::new(),
            query_cursor: 0,
            query_hint: String::new(),
            query_history: Vec::new(),
            completer,
            profiles: crate::util::aws_config::list_profiles(),
            selected_profile: 0,
            creating_graph: false,
        };
        app.start_view();
        app
    }

    fn start_view(&mut self) {
        self.abort_flag.store(true, Ordering::Relaxed);
        self.output_lines.clear();
        self.output_scroll = 0;
        self.items.clear();
        self.selected_item = 0;
        self.detail_scroll = 0;
        self.summary_header.clear();

        let menu = MenuItem::all()[self.selected_menu];

        // Check cache first — if we already computed this module, restore instantly
        if let Some(cached) = self.view_cache.get(&self.selected_menu) {
            self.output_lines = cached.output_lines.clone();
            self.items = cached.items.clone();
            self.summary_header = cached.summary_header.clone();
            self.processing = false;
            self.progress_rx = None;
            self.log_lines
                .push(format!("MODULE :: {} (cached)", menu.label()));
            return;
        }

        // Instant views
        if menu == MenuItem::GraphInfo {
            self.view_graph_info();
            self.processing = false;
            self.progress_rx = None;
            self.log_lines.push(format!("MODULE :: {}", menu.label()));
            self.view_cache.insert(
                self.selected_menu,
                CachedView {
                    output_lines: self.output_lines.clone(),
                    items: vec![],
                    summary_header: vec![],
                },
            );
            return;
        }

        // Create Graph wizard — instant, shows profile picker, don't cache
        if menu == MenuItem::CreateGraph {
            self.build_create_graph_view();
            self.processing = false;
            self.progress_rx = None;
            self.log_lines.push("MODULE :: CREATE GRAPH".into());
            return;
        }

        // Query REPL — instant, no background work, don't cache
        if menu == MenuItem::Query {
            self.output_lines.extend([
                d("  ╔══════════════════════════════════════════════╗"),
                h("  ║         Q U E R Y   R E P L                ║"),
                d("  ╚══════════════════════════════════════════════╝"),
                blank(),
                s("  Type a query below. Tab-completion is active."),
                s("  Examples:"),
                d("    who can do iam:CreateUser with *"),
                d("    can user/alice do s3:GetObject with *"),
                d("    preset privesc *"),
                blank(),
            ]);
            self.processing = false;
            self.progress_rx = None;
            self.log_lines.push("MODULE :: QUERY REPL".into());
            return;
        }

        // Background views
        let (tx, rx) = mpsc::channel();
        let abort = Arc::new(AtomicBool::new(false));
        self.abort_flag = Arc::clone(&abort);
        self.progress_rx = Some(rx);
        self.processing = true;

        self.output_lines
            .push(h(&format!("  Loading {}...", menu.label())));
        self.output_lines.push(d("  Press Esc to abort"));
        self.output_lines.push(blank());

        let graph = Arc::clone(&self.graph);
        std::thread::spawn(move || {
            match menu {
                MenuItem::Privesc => compute_privesc(&graph, &tx, &abort),
                MenuItem::Analysis => compute_analysis(&graph, &tx, &abort),
                MenuItem::Pathfinding => compute_pathfinding(&graph, &tx, &abort),
                MenuItem::ServiceAccess => compute_service_access(&graph, &tx, &abort),
                MenuItem::WrongAdmin => compute_wrong_admin(&graph, &tx, &abort),
                _ => {}
            }
            let _ = tx.send(ProgressMsg::Done);
        });
        self.log_lines
            .push(format!("COMPUTING :: {}", menu.label()));
    }

    fn poll_progress(&mut self) {
        let Some(ref rx) = self.progress_rx else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(ProgressMsg::Line(line)) => self.output_lines.push(line),
                Ok(ProgressMsg::Item(item)) => self.items.push(item),
                Ok(ProgressMsg::GraphReady(new_graph)) => {
                    // Replace the in-memory graph and refresh derived state
                    let g = Arc::new(*new_graph);
                    self.completer = GraphCompleter::from_graph(&g);
                    self.graph = g;
                    self.view_cache.clear();
                    self.creating_graph = false;
                    self.log_lines.push(format!(
                        "GRAPH LOADED :: {} nodes, {} edges",
                        self.graph.nodes.len(),
                        self.graph.edges.len()
                    ));
                }
                Ok(ProgressMsg::Done) => {
                    self.processing = false;
                    self.progress_rx = None;
                    // Move output_lines into summary_header for detail views
                    let menu = MenuItem::all()[self.selected_menu];
                    if menu.has_detail_view() {
                        self.summary_header = std::mem::take(&mut self.output_lines);
                    }
                    // Cache the completed results
                    self.view_cache.insert(
                        self.selected_menu,
                        CachedView {
                            output_lines: self.output_lines.clone(),
                            items: self.items.clone(),
                            summary_header: self.summary_header.clone(),
                        },
                    );
                    self.log_lines.push(format!(
                        "DONE :: {} ({} items)",
                        menu.label(),
                        self.items.len()
                    ));
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.processing = false;
                    self.progress_rx = None;
                    break;
                }
            }
        }
    }

    fn abort_current(&mut self) {
        if self.processing {
            self.abort_flag.store(true, Ordering::Relaxed);
            self.processing = false;
            self.progress_rx = None;
            self.output_lines.push(r("  ── ABORTED ──"));
            self.log_lines.push("ABORTED".into());
        }
    }

    /// Start creating a graph for the currently selected profile
    fn start_graph_creation(&mut self) {
        if self.profiles.is_empty() {
            return;
        }
        let profile = self.profiles[self.selected_profile].clone();

        self.output_lines.clear();
        self.output_lines.extend([
            d("  ╔══════════════════════════════════════════════╗"),
            h(&format!("  ║   SCANNING AWS :: {:<25}   ║", profile.name)),
            d("  ╚══════════════════════════════════════════════╝"),
            blank(),
            d("  Press Esc to abort"),
            blank(),
        ]);

        let (tx, rx) = mpsc::channel();
        let abort = Arc::new(AtomicBool::new(false));
        self.abort_flag = Arc::clone(&abort);
        self.progress_rx = Some(rx);
        self.processing = true;
        self.creating_graph = true;

        std::thread::spawn(move || {
            compute_create_graph(profile, tx, abort);
        });
        self.log_lines.push("COMPUTING :: graph create".to_string());
    }

    fn view_graph_info(&mut self) {
        let g = &self.graph;
        let users = g.nodes.iter().filter(|n| n.is_user()).count();
        let roles = g.nodes.iter().filter(|n| n.is_role()).count();
        let admins = g.nodes.iter().filter(|n| n.is_admin).count();

        self.output_lines.extend([
            d("  ╔══════════════════════════════════════════════╗"),
            h("  ║         I A M   G R A P H   C O R E        ║"),
            d("  ╚══════════════════════════════════════════════╝"),
            blank(),
            w(&format!("  ACCOUNT    {}", g.metadata.account_id)),
            s(&format!("  VERSION    {}", g.metadata.iam_recon_version)),
            blank(),
            d("  ── TOPOLOGY ──────────────────────────────────"),
            h(&format!("  PRINCIPALS {:>5}", g.nodes.len())),
            s(&format!("    users    {:>5}", users)),
            (
                format!("    roles    {:>5}", roles),
                Style::default().fg(Color::Magenta),
            ),
            r(&format!("    admins   {:>5}", admins)),
            y(&format!("  EDGES      {:>5}", g.edges.len())),
            s(&format!("  POLICIES   {:>5}", g.policies.len())),
            s(&format!("  GROUPS     {:>5}", g.groups.len())),
            blank(),
            d("  ── PRINCIPALS ────────────────────────────────"),
        ]);
        for node in &g.nodes {
            let tag = if node.is_admin { " [ADMIN]" } else { "" };
            let kind = if node.is_user() { "USR" } else { "ROL" };
            let sty = if node.is_admin {
                Style::default().fg(Color::Red).bold()
            } else if node.is_user() {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::Magenta)
            };
            self.output_lines.push(sl(
                &format!("  [{}] {}{}", kind, node.searchable_name(), tag),
                sty,
            ));
        }
    }

    fn build_create_graph_view(&mut self) {
        self.output_lines.extend([
            d("  ╔══════════════════════════════════════════════╗"),
            h("  ║        C R E A T E   G R A P H             ║"),
            d("  ╚══════════════════════════════════════════════╝"),
            blank(),
        ]);

        if self.profiles.is_empty() {
            self.output_lines.extend([
                r("  No AWS profiles found."),
                s("  Configure profiles in ~/.aws/config or ~/.aws/credentials,"),
                s("  or run: aws configure sso"),
            ]);
            return;
        }

        self.output_lines.extend([
            s(&format!(
                "  {} AWS profiles discovered from ~/.aws/config",
                self.profiles.len()
            )),
            d("  Use ↑↓ to select, Enter to scan, Esc to cancel"),
            blank(),
            d("  ── PROFILES ──────────────────────────────────"),
        ]);

        for (i, profile) in self.profiles.iter().enumerate() {
            let marker = if i == self.selected_profile {
                "▸ "
            } else {
                "  "
            };
            let cred_tag = if profile.has_credentials {
                " [creds]"
            } else {
                ""
            };
            let sso_tag = if profile.uses_sso { " [sso]" } else { "" };
            let region = profile
                .region
                .as_deref()
                .map(|r| format!(" ({})", r))
                .unwrap_or_default();
            let line_text = format!(
                "{}{}{}{}{}",
                marker, profile.name, region, cred_tag, sso_tag
            );
            let sty = if i == self.selected_profile {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if profile.has_credentials || profile.uses_sso {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            self.output_lines.push((format!("  {}", line_text), sty));
        }

        if self.creating_graph {
            self.output_lines.push(blank());
            self.output_lines
                .push(y("  Creating graph... see progress below."));
        }
    }
}

// ─── Background computations ────────────────────────────────────

macro_rules! check_abort {
    ($a:expr) => {
        if $a.load(Ordering::Relaxed) {
            return;
        }
    };
}

/// Create a graph from AWS using the given profile. Runs in a background
/// thread with its own tokio runtime; streams progress lines and a final
/// GraphReady message when done.
fn compute_create_graph(
    profile: crate::util::aws_config::AwsProfile,
    tx: mpsc::Sender<ProgressMsg>,
    abort: Arc<AtomicBool>,
) {
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╔══════════════════════════════════════════════╗",
    )));
    let _ = tx.send(ProgressMsg::Line(h(&format!(
        "  ║   SCANNING :: {:<30}",
        profile.name
    ))));
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╚══════════════════════════════════════════════╝",
    )));
    let _ = tx.send(ProgressMsg::Line(blank()));
    let _ = tx.send(ProgressMsg::Line(s(&format!(
        "  Profile: {}",
        profile.name
    ))));
    if let Some(region) = &profile.region {
        let _ = tx.send(ProgressMsg::Line(s(&format!("  Region:  {}", region))));
    }
    let _ = tx.send(ProgressMsg::Line(blank()));

    // Build a single-threaded tokio runtime for this background thread
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = tx.send(ProgressMsg::Line(r(&format!(
                "  Failed to create tokio runtime: {}",
                e
            ))));
            return;
        }
    };

    rt.block_on(async move {
        if abort.load(Ordering::Relaxed) {
            return;
        }
        let _ = tx.send(ProgressMsg::Line(y("  [1/4] Loading AWS credentials...")));

        let sdk_config = aws_config::from_env()
            .profile_name(&profile.name)
            .load()
            .await;

        if abort.load(Ordering::Relaxed) {
            return;
        }
        let _ = tx.send(ProgressMsg::Line(y(
            "  [2/4] Fetching IAM data (users, roles, policies)...",
        )));

        let checkers = crate::edges::CheckerKind::all();
        let result = crate::gathering::create_graph(&sdk_config, checkers, None, None).await;

        if abort.load(Ordering::Relaxed) {
            return;
        }

        match result {
            Ok(graph) => {
                let _ = tx.send(ProgressMsg::Line(y("  [3/4] Writing graph to disk...")));
                let path = crate::util::storage::get_default_graph_path(&graph.metadata.account_id);
                if let Err(e) = graph.store_to_disk(&path) {
                    let _ = tx.send(ProgressMsg::Line(r(&format!(
                        "  Failed to store graph: {}",
                        e
                    ))));
                    return;
                }
                let _ = tx.send(ProgressMsg::Line(g(&format!(
                    "  [4/4] Complete! {} nodes, {} edges (account {})",
                    graph.nodes.len(),
                    graph.edges.len(),
                    graph.metadata.account_id
                ))));
                let _ = tx.send(ProgressMsg::Line(blank()));
                let _ = tx.send(ProgressMsg::Line(g(
                    "  Graph is now live. Select a module to explore.",
                )));
                let _ = tx.send(ProgressMsg::GraphReady(Box::new(graph)));
            }
            Err(e) => {
                let _ = tx.send(ProgressMsg::Line(r(&format!("  ERROR: {}", e))));
                let _ = tx.send(ProgressMsg::Line(d(
                    "  Check AWS credentials and try again.",
                )));
            }
        }
    });
}

fn compute_privesc(graph: &Graph, tx: &mpsc::Sender<ProgressMsg>, abort: &AtomicBool) {
    use crate::querying::presets::privesc;
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╔══════════════════════════════════════════════╗",
    )));
    let _ = tx.send(ProgressMsg::Line(r(
        "  ║    P R I V I L E G E   E S C A L A T I O N  ║",
    )));
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╚══════════════════════════════════════════════╝",
    )));
    let _ = tx.send(ProgressMsg::Line(blank()));
    let total = graph.nodes.len();
    let mut found = false;
    for (i, node) in graph.nodes.iter().enumerate() {
        check_abort!(abort);
        let _ = tx.send(ProgressMsg::Line(d(&format!(
            "  scanning [{}/{}] {}...",
            i + 1,
            total,
            node.searchable_name()
        ))));
        if node.is_admin {
            let _ = tx.send(ProgressMsg::Line(r(&format!(
                "  ● {} [ADMIN]",
                node.searchable_name()
            ))));
            continue;
        }
        if let Some((can_esc, path)) = privesc::can_privesc(graph, node) {
            if can_esc {
                found = true;
                let _ = tx.send(ProgressMsg::Line(blank()));
                let _ = tx.send(ProgressMsg::Line(r(&format!(
                    "  ▶ {} CAN ESCALATE",
                    node.searchable_name()
                ))));
                for edge in &path {
                    let src = edge.source.split(':').last().unwrap_or(&edge.source);
                    let dst = edge
                        .destination
                        .split(':')
                        .last()
                        .unwrap_or(&edge.destination);
                    let _ = tx.send(ProgressMsg::Line(y(&format!(
                        "    {} ──[{}]──▶ {}",
                        src, edge.short_reason, dst
                    ))));
                }
            }
        }
    }
    if !found {
        let _ = tx.send(ProgressMsg::Line(g("  No escalation vectors detected.")));
    }
}

fn compute_analysis(graph: &Graph, tx: &mpsc::Sender<ProgressMsg>, abort: &AtomicBool) {
    let _ = tx.send(ProgressMsg::Line(d("  Running finding generators...")));
    check_abort!(abort);
    let report = crate::analysis::gen_report(graph);
    check_abort!(abort);

    let hi = report
        .findings
        .iter()
        .filter(|f| f.severity == crate::model::finding::Severity::High)
        .count();
    let md = report
        .findings
        .iter()
        .filter(|f| f.severity == crate::model::finding::Severity::Medium)
        .count();
    let lo = report
        .findings
        .iter()
        .filter(|f| f.severity == crate::model::finding::Severity::Low)
        .count();

    // Summary stats go as output lines (become summary_header)
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╔══════════════════════════════════════════════╗",
    )));
    let _ = tx.send(ProgressMsg::Line(y(
        "  ║     T H R E A T   A N A L Y S I S          ║",
    )));
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╚══════════════════════════════════════════════╝",
    )));
    let _ = tx.send(ProgressMsg::Line(blank()));
    let _ = tx.send(ProgressMsg::Line(w(&format!(
        "  FINDINGS  {}   |  {} HIGH  {} MEDIUM  {} LOW",
        report.findings.len(),
        hi,
        md,
        lo
    ))));
    let _ = tx.send(ProgressMsg::Line(d(
        "  Use ↑↓ to select, Enter to view detail, Esc to go back",
    )));

    for (i, f) in report.findings.iter().enumerate() {
        check_abort!(abort);
        let sev_sty = match f.severity {
            crate::model::finding::Severity::High => Style::default().fg(Color::Red).bold(),
            crate::model::finding::Severity::Medium => Style::default().fg(Color::Yellow),
            crate::model::finding::Severity::Low => Style::default().fg(Color::Blue),
        };
        let summary = format!("{:>2}. [{}] {}", i + 1, f.severity, f.title);
        let mut detail = vec![
            sl(&format!("[{}] {}", f.severity, f.title), sev_sty),
            blank(),
            w("  IMPACT"),
            s(&format!("  {}", f.impact)),
            blank(),
            w("  DESCRIPTION"),
        ];
        for line in word_wrap(&f.description, 70) {
            detail.push(s(&format!("  {}", line)));
        }
        if !f.recommendation.is_empty() {
            detail.push(blank());
            detail.push(w("  RECOMMENDATION"));
            for line in word_wrap(&f.recommendation, 70) {
                detail.push(g(&format!("  {}", line)));
            }
        }
        let _ = tx.send(ProgressMsg::Item(DetailItem {
            summary,
            summary_style: sev_sty,
            detail,
        }));
    }
}

fn compute_pathfinding(graph: &Graph, tx: &mpsc::Sender<ProgressMsg>, abort: &AtomicBool) {
    use crate::pathfinding::PathfindingMapper;

    let _ = tx.send(ProgressMsg::Line(d(
        "  Scanning against pathfinding.cloud database...",
    )));
    let total = graph.nodes.len();
    let mut all_matches = Vec::new();
    for (i, node) in graph.nodes.iter().enumerate() {
        check_abort!(abort);
        if node.is_admin {
            continue;
        }
        let _ = tx.send(ProgressMsg::Line(d(&format!(
            "  checking [{}/{}] {}...",
            i + 1,
            total,
            node.searchable_name()
        ))));
        all_matches.extend(PathfindingMapper::check_node(node));
    }
    check_abort!(abort);

    let _ = tx.send(ProgressMsg::Line(d(
        "  ╔══════════════════════════════════════════════╗",
    )));
    let _ = tx.send(ProgressMsg::Line(r(
        "  ║   A T T A C K   V E C T O R   D A T A B A S E",
    )));
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╚══════════════════════════════════════════════╝",
    )));
    let _ = tx.send(ProgressMsg::Line(blank()));
    let _ = tx.send(ProgressMsg::Line(s(&format!(
        "  {} paths in DB  |  {} matches",
        PathfindingMapper::path_count(),
        all_matches.len()
    ))));
    let _ = tx.send(ProgressMsg::Line(d(
        "  Use ↑↓ to select, Enter to view detail, Esc to go back",
    )));

    for matched in &all_matches {
        check_abort!(abort);
        let cat_sty = match matched.path.category {
            crate::pathfinding::EscalationCategory::SelfEscalation => {
                Style::default().fg(Color::Red).bold()
            }
            crate::pathfinding::EscalationCategory::PrincipalAccess => {
                Style::default().fg(Color::Red).bold()
            }
            crate::pathfinding::EscalationCategory::NewPassrole => {
                Style::default().fg(Color::Yellow).bold()
            }
            crate::pathfinding::EscalationCategory::ExistingPassrole => {
                Style::default().fg(Color::Yellow)
            }
            crate::pathfinding::EscalationCategory::CredentialAccess => {
                Style::default().fg(Color::Magenta)
            }
        };
        let summary = format!(
            "[{}] {} :: {}",
            matched.path.id, matched.node_name, matched.path.name
        );
        let mut detail = vec![
            sl(
                &format!("[{}] {}", matched.path.id, matched.path.name),
                cat_sty,
            ),
            blank(),
            w("  PRINCIPAL"),
            h(&format!("  {}", matched.node_arn)),
            blank(),
            w("  CATEGORY"),
            y(&format!("  {}", matched.path.category)),
            blank(),
            w("  REQUIRED PERMISSIONS"),
        ];
        for perm in &matched.matched_permissions {
            detail.push(s(&format!("  - {}", perm)));
        }
        detail.push(blank());
        detail.push(w("  DESCRIPTION"));
        for line in word_wrap(&matched.path.description, 70) {
            detail.push(s(&format!("  {}", line)));
        }
        if !matched.path.recommendation.is_empty() {
            detail.push(blank());
            detail.push(w("  RECOMMENDATION"));
            for line in word_wrap(&matched.path.recommendation, 70) {
                detail.push(g(&format!("  {}", line)));
            }
        }
        detail.push(blank());
        detail.push(w("  REFERENCE"));
        detail.push(h(&format!("  {}", matched.path.url())));

        let _ = tx.send(ProgressMsg::Item(DetailItem {
            summary,
            summary_style: cat_sty,
            detail,
        }));
    }
}

fn compute_service_access(graph: &Graph, tx: &mpsc::Sender<ProgressMsg>, abort: &AtomicBool) {
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╔══════════════════════════════════════════════╗",
    )));
    let _ = tx.send(ProgressMsg::Line(h(
        "  ║   S E R V I C E   T R U S T   M A P        ║",
    )));
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╚══════════════════════════════════════════════╝",
    )));
    let _ = tx.send(ProgressMsg::Line(blank()));
    check_abort!(abort);
    let map = crate::querying::presets::serviceaccess::compose_service_access_map(graph);
    if map.is_empty() {
        let _ = tx.send(ProgressMsg::Line(d(
            "  No service trust relationships found.",
        )));
    } else {
        let mut svcs: Vec<&String> = map.keys().collect();
        svcs.sort();
        for svc in svcs {
            check_abort!(abort);
            let roles = &map[svc];
            let _ = tx.send(ProgressMsg::Line(y(&format!(
                "  ▸ {} ({} roles)",
                svc,
                roles.len()
            ))));
            for role in roles {
                let sty = if role.is_admin {
                    Style::default().fg(Color::Red).bold()
                } else {
                    Style::default().fg(Color::Magenta)
                };
                let tag = if role.is_admin { " [ADMIN]" } else { "" };
                let _ = tx.send(ProgressMsg::Line(sl(
                    &format!("      {}{}", role.searchable_name(), tag),
                    sty,
                )));
            }
            let _ = tx.send(ProgressMsg::Line(blank()));
        }
    }
}

fn compute_wrong_admin(graph: &Graph, tx: &mpsc::Sender<ProgressMsg>, abort: &AtomicBool) {
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╔══════════════════════════════════════════════╗",
    )));
    let _ = tx.send(ProgressMsg::Line(y(
        "  ║   A N O M A L O U S   A D M I N S          ║",
    )));
    let _ = tx.send(ProgressMsg::Line(d(
        "  ╚══════════════════════════════════════════════╝",
    )));
    let _ = tx.send(ProgressMsg::Line(blank()));
    check_abort!(abort);
    let wrong = crate::querying::presets::wrongadmin::compose_wrong_admin_list(graph);
    if wrong.is_empty() {
        let _ = tx.send(ProgressMsg::Line(g("  All admin principals verified.")));
    } else {
        for (node, reasons) in &wrong {
            check_abort!(abort);
            let _ = tx.send(ProgressMsg::Line(r(&format!(
                "  ▶ {} — admin without AdministratorAccess",
                node.searchable_name()
            ))));
            for reason in reasons {
                let _ = tx.send(ProgressMsg::Line(d(&format!("    {}", reason))));
            }
            let _ = tx.send(ProgressMsg::Line(blank()));
        }
    }
}

fn word_wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let para = para.trim();
        if para.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut cur = String::new();
        for word in para.split_whitespace() {
            if cur.len() + word.len() + 1 > width && !cur.is_empty() {
                lines.push(cur);
                cur = String::new();
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
        if !cur.is_empty() {
            lines.push(cur);
        }
    }
    lines
}

fn truncate(text: &str, max: usize) -> String {
    let c: String = text.chars().filter(|c| *c != '\n').collect();
    if c.len() > max {
        format!("{}...", &c[..max])
    } else {
        c
    }
}

// ─── Main loop ──────────────────────────────────────────────────

/// Build an empty placeholder graph for when no graph is loaded
fn empty_graph(account_id: &str) -> Graph {
    use std::collections::HashMap;
    let metadata = crate::model::graph::GraphMetadata {
        account_id: account_id.to_string(),
        iam_recon_version: crate::model::graph::IAM_RECON_VERSION.to_string(),
        extra: HashMap::new(),
    };
    Graph::new(vec![], vec![], vec![], vec![], metadata)
}

pub fn run_tui(account_id: Option<&str>) -> anyhow::Result<()> {
    // Try to load an existing graph. If none, land on the Create Graph wizard.
    let (graph, has_existing) = match account_id {
        Some(id) => {
            let path = storage::get_default_graph_path(id);
            match Graph::load_from_disk(&path) {
                Ok(g) => (g, true),
                Err(_) => (empty_graph(id), false),
            }
        }
        None => (empty_graph("(not loaded)"), false),
    };

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut app = App::new(graph);
    // If there's no real graph, start the user at the Create Graph wizard
    if !has_existing {
        app.selected_menu = 0; // CreateGraph is index 0
        app.start_view();
    } else {
        // Skip past Create Graph to the first real module
        app.selected_menu = 1;
        app.start_view();
    }

    while app.running {
        app.poll_progress();
        terminal.draw(|frame| draw(frame, &app))?;
        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                handle_key(&mut app, key);
            }
        }
        app.tick += 1;
    }

    app.abort_flag.store(true, Ordering::Relaxed);
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

// ─── Drawing ────────────────────────────────────────────────────

fn draw(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(4),
        ])
        // status bar is 4 rows: top border + 2 lines content + bottom border
        .split(frame.area());

    draw_title_bar(frame, app, outer[0]);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(24), Constraint::Min(1)])
        .split(outer[1]);

    draw_menu(frame, app, main[0]);

    let menu = MenuItem::all()[app.selected_menu];
    if menu == MenuItem::Query {
        draw_query_view(frame, app, main[1]);
    } else if menu.has_detail_view() && !app.processing && !app.items.is_empty() {
        draw_detail_view(frame, app, main[1]);
    } else {
        draw_output(frame, app, main[1]);
    }

    draw_status_bar(frame, app, outer[2]);

    // Help overlay on top of everything
    if app.focus == Focus::Help {
        draw_help_overlay(frame);
    }
}

fn draw_title_bar(frame: &mut Frame, app: &App, area: Rect) {
    let bar = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(10, 10, 20)));

    let pulse = if app.tick % 20 < 10 { "●" } else { "○" };
    let module_label = format!("  [{}]", MenuItem::all()[app.selected_menu].label());
    let proc = if app.processing {
        let sp = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        format!("  {} PROCESSING", sp[(app.tick as usize / 2) % sp.len()])
    } else {
        String::new()
    };

    let text = Line::from(vec![
        Span::styled(" IAM-RECON ", Style::default().fg(Color::Cyan).bold()),
        Span::styled(":: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "ATTACK SURFACE ANALYZER ",
            Style::default().fg(Color::White),
        ),
        Span::styled(pulse, Style::default().fg(Color::Red)),
        Span::styled(module_label, Style::default().fg(Color::Yellow).bold()),
        Span::styled(proc, Style::default().fg(Color::Magenta).bold()),
    ]);
    frame.render_widget(Paragraph::new(text).block(bar), area);
}

fn draw_menu(frame: &mut Frame, app: &App, area: Rect) {
    let border_color = if app.focus == Focus::Menu {
        Color::Cyan
    } else {
        Color::Rgb(40, 40, 60)
    };

    let items: Vec<ListItem> = MenuItem::all()
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let c = format!("{}{}", m.icon(), m.label());
            let sty = if i == app.selected_menu {
                Style::default().fg(Color::Black).bg(Color::Cyan).bold()
            } else {
                Style::default().fg(Color::Rgb(120, 120, 140))
            };
            ListItem::new(c).style(sty)
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(" MODULES ", Style::default().fg(Color::Cyan)))
            .style(Style::default().bg(Color::Rgb(10, 10, 20))),
    );
    frame.render_widget(list, area);
}

fn draw_output(frame: &mut Frame, app: &App, area: Rect) {
    let border_color = if app.focus == Focus::Content {
        Color::Yellow
    } else {
        Color::Rgb(40, 40, 60)
    };
    let lines: Vec<Line> = app
        .output_lines
        .iter()
        .map(|(t, sty)| Line::from(Span::styled(t.as_str(), *sty)))
        .collect();
    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_color))
                .title(Span::styled(
                    format!(" {} ", MenuItem::all()[app.selected_menu].label()),
                    Style::default().fg(Color::Yellow).bold(),
                ))
                .style(Style::default().bg(Color::Rgb(10, 10, 20))),
        )
        .scroll((app.output_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

/// Split view: summary header + item list on top, detail panel on bottom
fn draw_detail_view(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // ── Top: summary header + selectable list ──
    let mut top_lines: Vec<Line> = app
        .summary_header
        .iter()
        .map(|(t, sty)| Line::from(Span::styled(t.as_str(), *sty)))
        .collect();
    top_lines.push(Line::from(""));

    for (i, item) in app.items.iter().enumerate() {
        let marker = if i == app.selected_item { "▸ " } else { "  " };
        let sty = if i == app.selected_item {
            Style::default().fg(Color::Black).bg(Color::Cyan).bold()
        } else {
            item.summary_style
        };
        top_lines.push(Line::from(Span::styled(
            format!("{}{}", marker, item.summary),
            sty,
        )));
    }

    let counter = format!(" {}/{} ", app.selected_item + 1, app.items.len());
    let top = Paragraph::new(top_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(40, 40, 60)))
                .title(Span::styled(
                    format!(" {} ", MenuItem::all()[app.selected_menu].label()),
                    Style::default().fg(Color::Yellow).bold(),
                ))
                .title_bottom(Span::styled(counter, Style::default().fg(Color::Cyan)))
                .style(Style::default().bg(Color::Rgb(10, 10, 20))),
        )
        .scroll((
            // Auto-scroll to keep selected item visible
            app.selected_item
                .saturating_sub(2)
                .saturating_add(app.summary_header.len()) as u16,
            0,
        ))
        .wrap(Wrap { trim: false });
    frame.render_widget(top, chunks[0]);

    // ── Bottom: detail of selected item ──
    let detail_lines: Vec<Line> = if let Some(item) = app.items.get(app.selected_item) {
        item.detail
            .iter()
            .map(|(t, sty)| Line::from(Span::styled(t.as_str(), *sty)))
            .collect()
    } else {
        vec![Line::from(Span::styled(
            "  Select an item above",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let bottom = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(40, 40, 60)))
                .title(Span::styled(
                    " DETAIL ",
                    Style::default().fg(Color::Magenta).bold(),
                ))
                .style(Style::default().bg(Color::Rgb(10, 10, 20))),
        )
        .scroll((app.detail_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(bottom, chunks[1]);
}

/// Query REPL view: output on top, input bar with ghost-text completion at bottom
fn draw_query_view(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(area);

    // Output panel
    let border_color = if app.focus == Focus::Content {
        Color::Yellow
    } else {
        Color::Rgb(40, 40, 60)
    };
    let lines: Vec<Line> = app
        .output_lines
        .iter()
        .map(|(t, sty)| Line::from(Span::styled(t.as_str(), *sty)))
        .collect();
    let output = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_color))
                .title(Span::styled(
                    " QUERY REPL ",
                    Style::default().fg(Color::Yellow).bold(),
                ))
                .style(Style::default().bg(Color::Rgb(10, 10, 20))),
        )
        .scroll((app.output_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(output, chunks[0]);

    // Input bar with hint
    let input_line = Line::from(vec![
        Span::styled(&app.query_input, Style::default().fg(Color::White)),
        Span::styled(&app.query_hint, Style::default().fg(Color::Rgb(60, 60, 80))),
    ]);

    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if app.focus == Focus::Content {
            Color::Cyan
        } else {
            Color::Rgb(40, 40, 60)
        }))
        .title(Span::styled(" > ", Style::default().fg(Color::Cyan).bold()))
        .style(Style::default().bg(Color::Rgb(10, 10, 20)));
    let input_para = Paragraph::new(input_line).block(input_block);
    frame.render_widget(input_para, chunks[1]);

    // Show cursor position
    if app.focus == Focus::Content {
        frame.set_cursor_position((chunks[1].x + 3 + app.query_cursor as u16, chunks[1].y + 1));
    }
}

/// Build a span for a keyboard hint: "[key] label"
fn kh(key: &'static str, label: &'static str) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {} ", key),
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::styled(format!(" {}  ", label), Style::default().fg(Color::Gray)),
    ]
}

fn kh_red(key: &'static str, label: &'static str) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {} ", key),
            Style::default().fg(Color::White).bg(Color::Red).bold(),
        ),
        Span::styled(format!(" {}  ", label), Style::default().fg(Color::Gray)),
    ]
}

fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    // Line 1: context-specific keybindings
    let keys_line: Line = match app.focus {
        Focus::QuitConfirm => {
            let mut spans = vec![Span::styled(
                "  Exit IAM Recon? ",
                Style::default().fg(Color::Red).bold(),
            )];
            spans.extend(kh_red("y", "confirm exit"));
            spans.extend(kh("any", "cancel"));
            Line::from(spans)
        }
        Focus::Help => Line::from(vec![
            Span::styled("  HELP  —  ", Style::default().fg(Color::Yellow).bold()),
            Span::styled(
                " any key ",
                Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
            ),
            Span::styled(" to close", Style::default().fg(Color::Gray)),
        ]),
        Focus::Menu => {
            let mut spans = vec![Span::raw(" ")];
            spans.extend(kh("↑↓", "move"));
            spans.extend(kh("Enter/→", "open module"));
            spans.extend(kh("1-7", "jump"));
            spans.extend(kh("?", "help"));
            spans.extend(kh_red("q", "quit"));
            Line::from(spans)
        }
        Focus::Content if app.processing => {
            let mut spans = vec![Span::raw(" ")];
            spans.extend(kh_red("Esc", "abort computation"));
            Line::from(spans)
        }
        Focus::Content => {
            let menu = MenuItem::all()[app.selected_menu];
            let has_items = menu.has_detail_view() && !app.items.is_empty();
            let mut spans = vec![Span::raw(" ")];
            spans.extend(kh("Esc/←", "back to menu"));
            if menu == MenuItem::Query {
                spans.extend(kh("Tab/→", "accept hint"));
                spans.extend(kh("Enter", "run query"));
                spans.extend(kh("↑", "history"));
            } else if has_items {
                spans.extend(kh("↑↓", "select finding"));
                spans.extend(kh("PgUp/PgDn", "scroll detail"));
            } else {
                spans.extend(kh("↑↓", "scroll"));
                spans.extend(kh("Home/End", "jump"));
            }
            spans.extend(kh("?", "help"));
            Line::from(spans)
        }
    };

    // Line 2: most recent log message
    let last_log = app.log_lines.last().map(|s| s.as_str()).unwrap_or("");
    let log_line = Line::from(Span::styled(
        format!("  > {}", last_log),
        Style::default().fg(Color::Rgb(80, 80, 100)),
    ));

    let title = match app.focus {
        Focus::Menu => " MENU KEYS ",
        Focus::Content => " KEYS ",
        Focus::QuitConfirm => " CONFIRM ",
        Focus::Help => " HELP ",
    };

    let bar = Paragraph::new(vec![keys_line, log_line]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(60, 60, 90)))
            .title(Span::styled(title, Style::default().fg(Color::Cyan).bold()))
            .style(Style::default().bg(Color::Rgb(10, 10, 20))),
    );
    frame.render_widget(bar, area);
}

/// Draw a centered help overlay with all keybindings
fn draw_help_overlay(frame: &mut Frame) {
    let area = frame.area();
    // Center a 70x22 box
    let w = 70u16.min(area.width.saturating_sub(4));
    let h = 22u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let overlay = Rect {
        x,
        y,
        width: w,
        height: h,
    };

    // Clear background
    frame.render_widget(Clear, overlay);

    let help_text = vec![
        Line::from(Span::styled(
            "  IAM-RECON KEYBINDINGS",
            Style::default().fg(Color::Cyan).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  NAVIGATION",
            Style::default().fg(Color::Yellow).bold(),
        )),
        Line::from(vec![
            Span::styled("    ↑↓ / j k       ", Style::default().fg(Color::Cyan)),
            Span::styled("move up/down", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("    Enter / →      ", Style::default().fg(Color::Cyan)),
            Span::styled("open module / accept", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("    Esc / ←        ", Style::default().fg(Color::Cyan)),
            Span::styled("back to menu (or abort)", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("    1 2 3 4 5 6 7  ", Style::default().fg(Color::Cyan)),
            Span::styled("jump to module by number", Style::default().fg(Color::Gray)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  SCROLLING",
            Style::default().fg(Color::Yellow).bold(),
        )),
        Line::from(vec![
            Span::styled("    PgUp / PgDn    ", Style::default().fg(Color::Cyan)),
            Span::styled("scroll by page", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("    Home / End     ", Style::default().fg(Color::Cyan)),
            Span::styled("jump to top/bottom", Style::default().fg(Color::Gray)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  QUERY REPL (module 2)",
            Style::default().fg(Color::Yellow).bold(),
        )),
        Line::from(vec![
            Span::styled("    Tab / →        ", Style::default().fg(Color::Cyan)),
            Span::styled("accept inline completion", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("    Enter          ", Style::default().fg(Color::Cyan)),
            Span::styled("run query", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("    ↑              ", Style::default().fg(Color::Cyan)),
            Span::styled(
                "previous query from history",
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  GLOBAL",
            Style::default().fg(Color::Yellow).bold(),
        )),
        Line::from(vec![
            Span::styled("    ?              ", Style::default().fg(Color::Cyan)),
            Span::styled("toggle this help overlay", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("    q              ", Style::default().fg(Color::Cyan)),
            Span::styled("quit (with confirmation)", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("    Ctrl+C         ", Style::default().fg(Color::Cyan)),
            Span::styled("force quit immediately", Style::default().fg(Color::Gray)),
        ]),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Color::Cyan))
                .title(Span::styled(
                    " ? HELP ",
                    Style::default().fg(Color::Yellow).bold(),
                ))
                .title_bottom(Span::styled(
                    " press any key to close ",
                    Style::default().fg(Color::DarkGray),
                ))
                .style(Style::default().bg(Color::Rgb(15, 15, 28))),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(help, overlay);
}

// ─── Key handling ───────────────────────────────────────────────

fn handle_key(app: &mut App, key: KeyEvent) {
    // ── Help overlay: any key closes it ──
    if app.focus == Focus::Help {
        app.focus = Focus::Menu;
        return;
    }

    // ── Quit confirmation dialog ──
    if app.focus == Focus::QuitConfirm {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.running = false,
            _ => {
                app.focus = Focus::Menu;
            } // anything else cancels
        }
        return;
    }

    // ── ? toggles help from anywhere (except Query input mode) ──
    let menu = MenuItem::all()[app.selected_menu];
    let in_query_input = menu == MenuItem::Query && app.focus == Focus::Content;
    if key.code == KeyCode::Char('?') && !in_query_input {
        app.focus = Focus::Help;
        return;
    }

    // ── Ctrl+C always exits immediately ──
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.abort_current();
        app.running = false;
        return;
    }

    // ── Processing: Esc aborts work, nothing else ──
    if app.processing {
        if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
            app.abort_current();
            app.focus = Focus::Menu;
        }
        return;
    }

    match app.focus {
        Focus::Menu => handle_key_menu(app, key),
        Focus::Content => handle_key_content(app, key),
        Focus::QuitConfirm => {} // handled above
        Focus::Help => {}        // handled above
    }
}

fn handle_key_menu(app: &mut App, key: KeyEvent) {
    match key.code {
        // Quit: show confirmation
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            app.focus = Focus::QuitConfirm;
        }
        // Esc from menu = also show quit confirmation
        KeyCode::Esc => {
            app.focus = Focus::QuitConfirm;
        }
        // Enter or right arrow = dive into the content panel
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            app.focus = Focus::Content;
        }
        // Navigate menu
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_menu > 0 {
                app.selected_menu -= 1;
                app.start_view();
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.selected_menu < MenuItem::all().len() - 1 {
                app.selected_menu += 1;
                app.start_view();
            }
        }
        // Number keys jump to module
        KeyCode::Char(c) if ('1'..='8').contains(&c) => {
            let idx = (c as usize) - ('1' as usize);
            if idx < MenuItem::all().len() {
                app.selected_menu = idx;
                app.start_view();
            }
        }
        _ => {}
    }
}

fn handle_key_content(app: &mut App, key: KeyEvent) {
    let menu = MenuItem::all()[app.selected_menu];

    // Create Graph wizard: navigate profiles, Enter to scan, Esc to cancel
    if menu == MenuItem::CreateGraph && !app.processing {
        handle_key_create_graph(app, key);
        return;
    }

    // Query REPL: typing mode — keys go into the input field
    if menu == MenuItem::Query {
        handle_key_query(app, key);
        return;
    }

    let has_items = menu.has_detail_view() && !app.items.is_empty();

    match key.code {
        // Esc or left arrow = back to menu
        KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => {
            app.focus = Focus::Menu;
        }
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            app.focus = Focus::QuitConfirm;
        }
        // Navigate items in detail views
        KeyCode::Up | KeyCode::Char('k') if has_items => {
            if app.selected_item > 0 {
                app.selected_item -= 1;
                app.detail_scroll = 0;
            }
        }
        KeyCode::Down | KeyCode::Char('j') if has_items => {
            if app.selected_item < app.items.len().saturating_sub(1) {
                app.selected_item += 1;
                app.detail_scroll = 0;
            }
        }
        // Scroll detail panel
        KeyCode::PageDown | KeyCode::Char('d') if has_items => {
            app.detail_scroll = app.detail_scroll.saturating_add(5);
        }
        KeyCode::PageUp | KeyCode::Char('u') if has_items => {
            app.detail_scroll = app.detail_scroll.saturating_sub(5);
        }
        // Scroll output (non-detail views)
        KeyCode::Up | KeyCode::Char('k') => {
            app.output_scroll = app.output_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.output_scroll = app.output_scroll.saturating_add(1);
        }
        KeyCode::PageDown | KeyCode::Char('d') => {
            app.output_scroll = app.output_scroll.saturating_add(10);
        }
        KeyCode::PageUp | KeyCode::Char('u') => {
            app.output_scroll = app.output_scroll.saturating_sub(10);
        }
        KeyCode::Home => {
            app.output_scroll = 0;
            app.detail_scroll = 0;
        }
        KeyCode::End => {
            app.output_scroll = app.output_lines.len().saturating_sub(5) as u16;
            if let Some(item) = app.items.get(app.selected_item) {
                app.detail_scroll = item.detail.len().saturating_sub(3) as u16;
            }
        }
        // Number keys jump back to menu + switch module
        KeyCode::Char(c) if ('1'..='8').contains(&c) => {
            let idx = (c as usize) - ('1' as usize);
            if idx < MenuItem::all().len() {
                app.selected_menu = idx;
                app.start_view();
                app.focus = Focus::Menu;
            }
        }
        _ => {}
    }
}

fn handle_key_create_graph(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.focus = Focus::Menu;
        }
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            app.focus = Focus::QuitConfirm;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_profile > 0 {
                app.selected_profile -= 1;
                app.start_view(); // re-render with new highlight
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.selected_profile + 1 < app.profiles.len() {
                app.selected_profile += 1;
                app.start_view();
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if !app.profiles.is_empty() {
                app.start_graph_creation();
            }
        }
        KeyCode::PageUp => {
            app.selected_profile = app.selected_profile.saturating_sub(5);
            app.start_view();
        }
        KeyCode::PageDown => {
            app.selected_profile =
                (app.selected_profile + 5).min(app.profiles.len().saturating_sub(1));
            app.start_view();
        }
        _ => {}
    }
}

fn handle_key_query(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.focus = Focus::Menu;
        }
        // Tab or Right-arrow: accept the hint
        KeyCode::Tab | KeyCode::Right if !app.query_hint.is_empty() => {
            app.query_input.push_str(&app.query_hint);
            app.query_cursor = app.query_input.len();
            app.query_hint.clear();
            update_query_hint(app);
        }
        // Enter: execute the query
        KeyCode::Enter => {
            let input = app.query_input.trim().to_string();
            if input.is_empty() {
                return;
            }

            app.query_history.push(input.clone());
            app.output_lines.push(h(&format!("  > {}", input)));

            match crate::querying::query_actions::execute_query(&app.graph, &input) {
                Ok(results) => {
                    if results.is_empty() {
                        app.output_lines.push(d("  No results."));
                    } else {
                        for result in &results {
                            let name = result.node.searchable_name();
                            if result.allowed {
                                if result.edge_list.is_empty() {
                                    app.output_lines
                                        .push(g(&format!("  ALLOW {} direct", name)));
                                } else {
                                    let hops = result.edge_list.len();
                                    let via: Vec<String> = result
                                        .edge_list
                                        .iter()
                                        .map(|e| {
                                            format!(
                                                "{}[{}]",
                                                e.destination.split(':').last().unwrap_or("?"),
                                                e.short_reason
                                            )
                                        })
                                        .collect();
                                    app.output_lines.push(g(&format!(
                                        "  ALLOW {} via {} hop(s): {}",
                                        name,
                                        hops,
                                        via.join(" -> ")
                                    )));
                                }
                            } else {
                                app.output_lines.push(r(&format!("  DENY  {}", name)));
                            }
                        }
                    }
                }
                Err(e) => {
                    app.output_lines.push(r(&format!("  Error: {}", e)));
                }
            }
            app.output_lines.push(blank());
            app.output_scroll = app.output_lines.len().saturating_sub(5) as u16;
            app.query_input.clear();
            app.query_cursor = 0;
            app.query_hint.clear();
        }
        KeyCode::Backspace => {
            if app.query_cursor > 0 {
                app.query_input.remove(app.query_cursor - 1);
                app.query_cursor -= 1;
                update_query_hint(app);
            }
        }
        KeyCode::Char(c) => {
            app.query_input.insert(app.query_cursor, c);
            app.query_cursor += 1;
            update_query_hint(app);
        }
        KeyCode::PageUp => {
            app.output_scroll = app.output_scroll.saturating_sub(10);
        }
        KeyCode::PageDown => {
            app.output_scroll = app.output_scroll.saturating_add(10);
        }
        KeyCode::Up => {
            if let Some(prev) = app.query_history.last() {
                app.query_input = prev.clone();
                app.query_cursor = app.query_input.len();
                update_query_hint(app);
            }
        }
        _ => {}
    }
}

fn update_query_hint(app: &mut App) {
    let before = &app.query_input[..app.query_cursor];
    let word_start = before.rfind(' ').map(|i| i + 1).unwrap_or(0);
    let word = &before[word_start..];

    if word.len() < 2 {
        app.query_hint.clear();
        return;
    }

    let completions = app.completer.complete_word(word);
    if let Some(first) = completions.first() {
        if first.len() > word.len() {
            app.query_hint = first[word.len()..].to_string();
        } else {
            app.query_hint.clear();
        }
    } else {
        app.query_hint.clear();
    }
}
