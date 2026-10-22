-- migrations/001_init.sql
-- PostgreSQL. Idempotente: a API roda este arquivo toda vez que inicia.

-- ---------- packets: um registro por pacote capturado ----------
CREATE TABLE IF NOT EXISTS packets (
    id       BIGSERIAL    PRIMARY KEY,                 -- i64 no Rust (PacketRow.id)
    ts       TIMESTAMPTZ  NOT NULL DEFAULT now(),      -- DateTime<Utc>; o INSERT não envia ts
    protocol TEXT         NOT NULL
             CHECK (protocol ~ '^[A-Za-z0-9]{1,10}$'), -- mesma regra do add_packet
    src      INET         NOT NULL,                    -- a API faz $2::inet e host(src)
    dst      INET         NOT NULL
);

-- retenção: DELETE ... WHERE ts < ...
CREATE INDEX IF NOT EXISTS idx_packets_ts       ON packets (ts);
-- filtro por IP: WHERE src = ... OR dst = ...
CREATE INDEX IF NOT EXISTS idx_packets_src      ON packets (src);
CREATE INDEX IF NOT EXISTS idx_packets_dst      ON packets (dst);
-- filtro por protocolo
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets (protocol);

-- ---------- devices: um registro por IP visto na rede ----------
CREATE TABLE IF NOT EXISTS devices (
    ip         INET         PRIMARY KEY,               -- exigido pelo ON CONFLICT (ip)
    first_seen TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    packets    BIGINT       NOT NULL DEFAULT 1         -- i64 no Rust; o INSERT inicial conta 1
);

-- GET /api/devices ordena por last_seen DESC
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen DESC);

-- ---------- flows: quem fala com quem, por protocolo ----------
CREATE TABLE IF NOT EXISTS flows (
    src        INET         NOT NULL,
    dst        INET         NOT NULL,
    protocol   TEXT         NOT NULL,
    first_seen TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    packets    BIGINT       NOT NULL DEFAULT 1,
    PRIMARY KEY (src, dst, protocol)                   -- exigido pelo ON CONFLICT (src, dst, protocol)
);
