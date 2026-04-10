use axum::response::Html;
use axum::routing::get;
use axum::Router;

use crate::model::graph::Graph;
use crate::visualization::interactive;

/// Serve the interactive visualization in a browser
pub async fn serve_interactive(graph: &Graph) -> anyhow::Result<()> {
    let graph_json = interactive::graph_to_visjs_json(graph);
    let json_str = serde_json::to_string(&graph_json)?;

    // Inject graph data into HTML template
    let html = interactive::INTERACTIVE_HTML.replace(
        "window.__IAM_RECON_DATA__",
        &format!("window.__IAM_RECON_DATA__ = {}", json_str),
    );

    let html_clone = html.clone();
    let app = Router::new().route(
        "/",
        get(move || {
            let h = html_clone.clone();
            async move { Html(h) }
        }),
    );

    // Find an available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    println!("Interactive visualization available at: http://{}", addr);
    println!("Press Ctrl+C to stop the server.");

    // Open browser
    let url = format!("http://{}", addr);
    if let Err(e) = open::that(&url) {
        tracing::warn!(
            "Failed to open browser: {}. Navigate to {} manually.",
            e,
            url
        );
    }

    axum::serve(listener, app).await?;

    Ok(())
}
