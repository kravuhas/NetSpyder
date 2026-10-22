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

// portas que merecem atenção: (porta, descrição, severidade)
// são indicadores de risco/exposição, não prova de ataque
const WATCH: &[(i32, &str, &str)] = &[
    (21, "FTP (texto claro)", "LOW"),
    (23, "Telnet (texto claro)", "LOW"),
    (445, "SMB exposto", "MEDIUM"),
    (3389, "RDP (acesso remoto)", "MEDIUM"),
    (4444, "Porta comum em payloads de acesso remoto", "MEDIUM"),
    (5555, "ADB / backdoors", "MEDIUM"),
    (6667, "IRC (usado por botnets antigas)", "MEDIUM"),
    (12345, "Porta associada a backdoors", "MEDIUM"),
    (31337, "Porta associada a backdoors", "MEDIUM"),
];

// ---------- tipos ----------

#[derive(Deserialize)]
struct NewPacket {
    protocol: String,
    src: String,
    dst: String,
    // campos opcionais: sniffers antigos continuam funcionando
    src_port: Option<i32>,
    dst_port: Option<i32>,
    length: Option<i32>,
    ttl: Option<i32>,
    flags: Option<i32>,
    icmp_type: Option<i32>,
    icmp_code: Option<i32>,
}

#[derive(Serialize, FromRow)]
struct PacketRow {
    id: i64,
    #[serde(rename = "timestamp")]
    ts: DateTime<Utc>,
    protocol: String,
    src: String,
    dst: String,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    length: Option<i32>,
    ttl: Option<i32>,
    flags: Option<i32>,
    icmp_type: Option<i32>,
    icmp_code: Option<i32>,
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
    port: Option<i32>,
    flag: Option<String>, // FIN, SYN, RST, PSH, ACK ou URG
    limit: Option<i64>,
    before: Option<i64>, // paginação: traga ids menores que este
}

#[derive(Deserialize)]
struct Page {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Deserialize)]
struct SecQuery {
    minutes: Option<i64>,
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

    // aplica as migrações em ordem (todas idempotentes)
    for sql in [
        include_str!("../migrations/001_init.sql"),
        include_str!("../migrations/002_security.sql"),
    ] {
        sqlx::raw_sql(sql)
            .execute(&pool)
            .await
            .expect("falha ao aplicar migração");
    }

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
        .route("/api/security", get(security))
        .with_state(pool);

    // 127.0.0.1: só esta máquina acessa (a API ainda não tem autenticação)
    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("API do sniffer em http://{addr} (retenção: {days} dias)");
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

fn in_range(v: Option<i32>, max: i32) -> bool {
    v.map_or(true, |x| (0..=max).contains(&x))
}

// POST /api/packets
async fn add_packet(State(pool): State<PgPool>, Json(p): Json<NewPacket>) -> StatusCode {
    let protocolo_valido = !p.protocol.is_empty()
        && p.protocol.len() <= 10
        && p.protocol.chars().all(|c| c.is_ascii_alphanumeric());

    let campos_validos = in_range(p.src_port, 65535)
        && in_range(p.dst_port, 65535)
        && in_range(p.length, 65535)
        && in_range(p.ttl, 255)
        && in_range(p.flags, 255)
        && in_range(p.icmp_type, 255)
        && in_range(p.icmp_code, 255);

    if !protocolo_valido
        || !campos_validos
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

    sqlx::query(
        "INSERT INTO packets
            (protocol, src, dst, src_port, dst_port, length, ttl, flags, icmp_type, icmp_code)
         VALUES ($1, $2::inet, $3::inet, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&p.protocol)
    .bind(&p.src)
    .bind(&p.dst)
    .bind(p.src_port)
    .bind(p.dst_port)
    .bind(p.length)
    .bind(p.ttl)
    .bind(p.flags)
    .bind(p.icmp_type)
    .bind(p.icmp_code)
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

// GET /api/packets?ip=1.2.3.4&protocol=TCP&port=443&flag=SYN&limit=50&before=1234
async fn list_packets(
    State(pool): State<PgPool>,
    Query(f): Query<PacketFilter>,
) -> Result<Json<Vec<PacketRow>>, StatusCode> {
    if let Some(ip) = &f.ip {
        if ip.parse::<Ipv4Addr>().is_err() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if !in_range(f.port, 65535) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mask: Option<i32> = match f.flag.as_deref().map(|s| s.to_ascii_uppercase()) {
        None => None,
        Some(s) => match s.as_str() {
            "FIN" => Some(1),
            "SYN" => Some(2),
            "RST" => Some(4),
            "PSH" => Some(8),
            "ACK" => Some(16),
            "URG" => Some(32),
            _ => return Err(StatusCode::BAD_REQUEST),
        },
    };
    let limit = f.limit.unwrap_or(100).clamp(1, MAX_LIMIT);

    sqlx::query_as::<_, PacketRow>(
        "SELECT id, ts, protocol, host(src) AS src, host(dst) AS dst,
                src_port, dst_port, length, ttl, flags, icmp_type, icmp_code
         FROM packets
         WHERE ($1::text IS NULL OR src = $1::inet OR dst = $1::inet)
           AND ($2::text IS NULL OR protocol = upper($2))
           AND ($3::bigint IS NULL OR id < $3)
           AND ($5::int IS NULL OR src_port = $5 OR dst_port = $5)
           AND ($6::int IS NULL OR (flags IS NOT NULL AND (flags & $6) = $6))
         ORDER BY id DESC
         LIMIT $4",
    )
    .bind(f.ip)
    .bind(f.protocol)
    .bind(f.before)
    .bind(limit)
    .bind(f.port)
    .bind(mask)
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

// GET /api/security?minutes=10
// agregados para detecção: varredura de portas, portas de risco, flags TCP e ICMP
async fn security(
    State(pool): State<PgPool>,
    Query(q): Query<SecQuery>,
) -> Result<Json<Value>, StatusCode> {
    let erro = |e: sqlx::Error| {
        eprintln!("erro em /api/security: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let mins = q.minutes.unwrap_or(10).clamp(1, 1440) as i32;

    // SYN sem ACK para muitas portas diferentes do mesmo destino
    let scans: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT host(src), host(dst), COUNT(DISTINCT dst_port), COUNT(*)
         FROM packets
         WHERE ts > now() - make_interval(mins => $1)
           AND protocol = 'TCP' AND flags IS NOT NULL AND (flags & 18) = 2
           AND dst_port IS NOT NULL
         GROUP BY src, dst
         HAVING COUNT(DISTINCT dst_port) >= 15
         ORDER BY 3 DESC LIMIT 20",
    )
    .bind(mins)
    .fetch_all(&pool)
    .await
    .map_err(erro)?;

    let ports: Vec<i32> = WATCH.iter().map(|w| w.0).collect();
    let risky: Vec<(i32, i64, i64)> = sqlx::query_as(
        "SELECT dst_port, COUNT(*), COUNT(DISTINCT src)
         FROM packets
         WHERE ts > now() - make_interval(mins => $1) AND dst_port = ANY($2)
         GROUP BY dst_port ORDER BY 2 DESC",
    )
    .bind(mins)
    .bind(&ports)
    .fetch_all(&pool)
    .await
    .map_err(erro)?;

    let top: Vec<(i32, i64)> = sqlx::query_as(
        "SELECT dst_port, COUNT(*) FROM packets
         WHERE ts > now() - make_interval(mins => $1) AND dst_port IS NOT NULL
         GROUP BY dst_port ORDER BY 2 DESC LIMIT 10",
    )
    .bind(mins)
    .fetch_all(&pool)
    .await
    .map_err(erro)?;

    let c: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            COUNT(*) FILTER (WHERE protocol = 'TCP' AND flags IS NOT NULL AND (flags & 18) = 2),
            COUNT(*) FILTER (WHERE flags IS NOT NULL AND (flags & 4) = 4),
            COUNT(*) FILTER (WHERE flags IS NOT NULL AND (flags & 1) = 1),
            COUNT(*) FILTER (WHERE protocol = 'ICMP' AND icmp_type = 3)
         FROM packets WHERE ts > now() - make_interval(mins => $1)",
    )
    .bind(mins)
    .fetch_one(&pool)
    .await
    .map_err(erro)?;

    let label = |p: i32| {
        WATCH
            .iter()
            .find(|w| w.0 == p)
            .map(|w| (w.1, w.2))
            .unwrap_or(("", "INFO"))
    };

    Ok(Json(json!({
        "minutes": mins,
        "port_scans": scans.into_iter()
            .map(|(s, d, p, n)| json!({ "src": s, "dst": d, "ports": p, "syns": n }))
            .collect::<Vec<_>>(),
        "risky_ports": risky.into_iter()
            .map(|(p, n, s)| {
                let (l, sev) = label(p);
                json!({ "port": p, "label": l, "severity": sev, "packets": n, "sources": s })
            })
            .collect::<Vec<_>>(),
        "top_ports": top.into_iter()
            .map(|(p, n)| json!({ "port": p, "packets": n }))
            .collect::<Vec<_>>(),
        "flags": { "syn": c.0, "rst": c.1, "fin": c.2, "icmp_unreachable": c.3 },
        "watchlist": WATCH.iter()
            .map(|w| json!({ "port": w.0, "label": w.1, "severity": w.2 }))
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
