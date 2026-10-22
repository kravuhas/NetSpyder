use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

const MAX_LIMIT: i64 = 1_000;

// ---------- tipos ----------

#[derive(Deserialize)]
struct NewPacket {
    protocol: String,
    src: String,
    dst: String,
}

#[derive(Serialize, FromRow)]
struct PacketRow {
    id: i64,
    #[serde(rename = "timestamp")]
    ts: DateTime<Utc>,
    protocol: String,
    src: String,
    dst: String,
}

#[derive(Serialize, FromRow)]
struct DeviceRow {
    ip: String,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    packets: i64,
}

#[derive(Deserialize)]
struct PacketFilter {
    ip: Option<String>,
    protocol: Option<String>,
    limit: Option<i64>,
    before: Option<i64>, // paginação: traga ids menores que este
}

#[derive(Deserialize)]
struct Page {
    limit: Option<i64>,
    offset: Option<i64>,
}

// ---------- main ----------

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let url = std::env::var("DATABASE_URL").expect("defina DATABASE_URL no .env");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("não consegui conectar no PostgreSQL (o container está rodando?)");

    // cria as tabelas se ainda não existirem (o script é idempotente)
    sqlx::raw_sql(include_str!("../migrations/001_init.sql"))
        .execute(&pool)
        .await
        .expect("falha ao criar as tabelas");

    let days: i32 = std::env::var("RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);
    spawn_retention(pool.clone(), days);

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api", get(status))
        .route(
            "/api/packets",
            get(list_packets).post(add_packet).delete(clear_all),
        )
        .route("/api/devices", get(list_devices))
        .route("/api/stats", get(stats))
        .with_state(pool);

    // 127.0.0.1: só esta máquina acessa (a API ainda não tem autenticação)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("API do sniffer em http://127.0.0.1:3000 (retenção: {days} dias)");
    axum::serve(listener, app).await.unwrap();
}

// apaga pacotes antigos a cada hora
fn spawn_retention(pool: PgPool, days: i32) {
    tokio::spawn(async move {
        loop {
            match sqlx::query("DELETE FROM packets WHERE ts < now() - make_interval(days => $1)")
                .bind(days)
                .execute(&pool)
                .await
            {
                Ok(r) if r.rows_affected() > 0 => {
                    println!("retenção: {} pacotes antigos removidos", r.rows_affected())
                }
                Ok(_) => {}
                Err(e) => eprintln!("erro na retenção: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

// ---------- handlers ----------

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn status(State(pool): State<PgPool>) -> Json<Value> {
    let db_ok = sqlx::query("SELECT 1").execute(&pool).await.is_ok();
    Json(json!({ "status": "ok", "service": "sniffer-api", "database": db_ok }))
}

// POST /api/packets
async fn add_packet(State(pool): State<PgPool>, Json(p): Json<NewPacket>) -> StatusCode {
    let protocolo_valido = !p.protocol.is_empty()
        && p.protocol.len() <= 10
        && p.protocol.chars().all(|c| c.is_ascii_alphanumeric());

    if !protocolo_valido
        || p.src.parse::<Ipv4Addr>().is_err()
        || p.dst.parse::<Ipv4Addr>().is_err()
    {
        return StatusCode::BAD_REQUEST;
    }

    match save_packet(&pool, &p).await {
        Ok(()) => StatusCode::CREATED,
        Err(e) => {
            eprintln!("erro ao salvar: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// grava o pacote, atualiza os dispositivos e o fluxo, tudo numa transação
async fn save_packet(pool: &PgPool, p: &NewPacket) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("INSERT INTO packets (protocol, src, dst) VALUES ($1, $2::inet, $3::inet)")
        .bind(&p.protocol)
        .bind(&p.src)
        .bind(&p.dst)
        .execute(&mut *tx)
        .await?;

    // ordem fixa + sem duplicar: evita deadlock entre transações concorrentes
    let mut ips = vec![p.src.as_str(), p.dst.as_str()];
    ips.sort();
    ips.dedup();
    for ip in ips {
        sqlx::query(
            "INSERT INTO devices (ip) VALUES ($1::inet)
             ON CONFLICT (ip) DO UPDATE
             SET last_seen = now(), packets = devices.packets + 1",
        )
        .bind(ip)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        "INSERT INTO flows (src, dst, protocol) VALUES ($1::inet, $2::inet, $3)
         ON CONFLICT (src, dst, protocol) DO UPDATE
         SET last_seen = now(), packets = flows.packets + 1",
    )
    .bind(&p.src)
    .bind(&p.dst)
    .bind(&p.protocol)
    .execute(&mut *tx)
    .await?;

    tx.commit().await
}

// GET /api/packets?ip=1.2.3.4&protocol=TCP&limit=50&before=1234
async fn list_packets(
    State(pool): State<PgPool>,
    Query(f): Query<PacketFilter>,
) -> Result<Json<Vec<PacketRow>>, StatusCode> {
    if let Some(ip) = &f.ip {
        if ip.parse::<Ipv4Addr>().is_err() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let limit = f.limit.unwrap_or(100).clamp(1, MAX_LIMIT);

    sqlx::query_as::<_, PacketRow>(
        "SELECT id, ts, protocol, host(src) AS src, host(dst) AS dst
         FROM packets
         WHERE ($1::text IS NULL OR src = $1::inet OR dst = $1::inet)
           AND ($2::text IS NULL OR protocol = upper($2))
           AND ($3::bigint IS NULL OR id < $3)
         ORDER BY id DESC
         LIMIT $4",
    )
    .bind(f.ip)
    .bind(f.protocol)
    .bind(f.before)
    .bind(limit)
    .fetch_all(&pool)
    .await
    .map(Json)
    .map_err(|e| {
        eprintln!("erro na consulta: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

// GET /api/devices?limit=50&offset=0
async fn list_devices(
    State(pool): State<PgPool>,
    Query(pg): Query<Page>,
) -> Result<Json<Vec<DeviceRow>>, StatusCode> {
    let limit = pg.limit.unwrap_or(50).clamp(1, MAX_LIMIT);
    let offset = pg.offset.unwrap_or(0).max(0);

    sqlx::query_as::<_, DeviceRow>(
        "SELECT host(ip) AS ip, first_seen, last_seen, packets
         FROM devices ORDER BY last_seen DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map(Json)
    .map_err(|e| {
        eprintln!("erro na consulta: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

// GET /api/stats
async fn stats(State(pool): State<PgPool>) -> Result<Json<Value>, StatusCode> {
    let erro = |e: sqlx::Error| {
        eprintln!("erro nas estatísticas: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    };

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM packets")
        .fetch_one(&pool)
        .await
        .map_err(erro)?;

    let protos: Vec<(String, i64)> =
        sqlx::query_as("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
            .fetch_all(&pool)
            .await
            .map_err(erro)?;
    let por_protocolo: HashMap<String, i64> = protos.into_iter().collect();

    let top: Vec<(String, i64)> = sqlx::query_as(
        "SELECT ip, COUNT(*) AS n FROM (
             SELECT host(src) AS ip FROM packets
             UNION ALL
             SELECT host(dst) FROM packets
         ) t GROUP BY ip ORDER BY n DESC LIMIT 5",
    )
    .fetch_all(&pool)
    .await
    .map_err(erro)?;

    Ok(Json(json!({
        "total": total,
        "por_protocolo": por_protocolo,
        "top_ips": top
            .into_iter()
            .map(|(ip, n)| json!({ "ip": ip, "pacotes": n }))
            .collect::<Vec<_>>()
    })))
}

// DELETE /api/packets -> apaga tudo (sem autenticação ainda: Etapa 6)
async fn clear_all(State(pool): State<PgPool>) -> StatusCode {
    match sqlx::query("TRUNCATE packets, devices, flows")
        .execute(&pool)
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}