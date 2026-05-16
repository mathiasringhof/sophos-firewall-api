use std::net::SocketAddr;

use sophos_firewall_api::{HttpTransport, SophosClient};
use sophos_firewall_web::{AppState, Config, routes};

#[tokio::main]
async fn main() -> sophos_firewall_web::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sophos_firewall_web=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let connection = config.connection;
    let transport = HttpTransport::from_connection(&connection)?;
    let client = SophosClient::new(connection, transport);
    let bind = config.bind;

    let app = routes(AppState::new(client));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "starting Sophos Firewall web API");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
