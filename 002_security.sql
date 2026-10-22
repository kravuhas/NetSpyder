-- migrations/002_security.sql
-- Campos extraídos do cabeçalho IP/TCP/UDP/ICMP. Todos opcionais (NULL em pacotes antigos).
-- Idempotente: a API aplica este arquivo toda vez que inicia.

ALTER TABLE packets
    ADD COLUMN IF NOT EXISTS src_port  INTEGER CHECK (src_port  BETWEEN 0 AND 65535),
    ADD COLUMN IF NOT EXISTS dst_port  INTEGER CHECK (dst_port  BETWEEN 0 AND 65535),
    ADD COLUMN IF NOT EXISTS length    INTEGER CHECK (length    BETWEEN 0 AND 65535),  -- tamanho total do pacote IP (bytes)
    ADD COLUMN IF NOT EXISTS ttl       INTEGER CHECK (ttl       BETWEEN 0 AND 255),
    ADD COLUMN IF NOT EXISTS flags     INTEGER CHECK (flags     BETWEEN 0 AND 255),    -- byte de flags TCP: FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
    ADD COLUMN IF NOT EXISTS icmp_type INTEGER CHECK (icmp_type BETWEEN 0 AND 255),
    ADD COLUMN IF NOT EXISTS icmp_code INTEGER CHECK (icmp_code BETWEEN 0 AND 255);

-- filtro por porta e consultas de portas mais usadas
CREATE INDEX IF NOT EXISTS idx_packets_dst_port ON packets (dst_port);

-- detecção de varredura: só indexa SYNs sem ACK (índice parcial, bem pequeno)
CREATE INDEX IF NOT EXISTS idx_packets_syn
    ON packets (ts, src, dst, dst_port)
    WHERE flags IS NOT NULL AND (flags & 18) = 2;
