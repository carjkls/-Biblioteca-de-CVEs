-- =============================================================
-- Biblioteca de CVEs - Schema do banco (PostgreSQL 16)
-- =============================================================
-- Execute com: psql -U postgres -d biblioteca_cves -f sql/01_schema.sql

DROP TABLE IF EXISTS alertas_seguranca, log_acessos, honeypots, termos_suspeitos,
                     referencias, notas, cve_tecnologias, tecnologias, cves, usuarios CASCADE;

-- pgcrypto: hash de senha com bcrypt direto no banco (crypt + gen_salt('bf'))
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -------------------------------------------------------------
-- Usuários do sistema (login)
-- -------------------------------------------------------------
CREATE TABLE usuarios (
    id          SERIAL PRIMARY KEY,
    nome        VARCHAR(100) NOT NULL,
    email       VARCHAR(150) NOT NULL UNIQUE,
    senha_hash  TEXT         NOT NULL,
    papel       VARCHAR(10)  NOT NULL DEFAULT 'dev' CHECK (papel IN ('admin', 'dev')),
    ativo       BOOLEAN      NOT NULL DEFAULT TRUE,
    criado_em   TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------------
-- CVEs (tabela principal do CRUD)
-- codigo aceita CVE-AAAA-NNNN (públicas) e INT-AAAA-NNN (avisos internos)
-- severidade é calculada automaticamente a partir do CVSS (coluna gerada)
-- -------------------------------------------------------------
CREATE TABLE cves (
    id               SERIAL PRIMARY KEY,
    codigo           VARCHAR(20)  NOT NULL UNIQUE
                     CHECK (codigo ~ '^(CVE|INT)-[0-9]{4}-[0-9]{3,7}$'),
    titulo           VARCHAR(200) NOT NULL,
    descricao        TEXT,
    cvss             NUMERIC(3,1) CHECK (cvss BETWEEN 0 AND 10),
    severidade       VARCHAR(12) GENERATED ALWAYS AS (
                         CASE
                             WHEN cvss IS NULL THEN 'desconhecida'
                             WHEN cvss >= 9.0  THEN 'critica'
                             WHEN cvss >= 7.0  THEN 'alta'
                             WHEN cvss >= 4.0  THEN 'media'
                             ELSE 'baixa'
                         END) STORED,
    data_publicacao  DATE,
    link_referencia  TEXT,
    origem           VARCHAR(10)  NOT NULL DEFAULT 'manual' CHECK (origem IN ('manual', 'telegram')),
    telegram_msg_id  BIGINT,
    criado_por       INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
    criado_em        TIMESTAMP    NOT NULL DEFAULT NOW(),
    atualizado_em    TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cves_severidade ON cves (severidade);
CREATE INDEX idx_cves_data       ON cves (data_publicacao);

-- -------------------------------------------------------------
-- Tecnologias afetadas (Node.js, OpenSSL, Log4j...) - relação N:N com cves
-- -------------------------------------------------------------
CREATE TABLE tecnologias (
    id    SERIAL PRIMARY KEY,
    nome  VARCHAR(60) NOT NULL UNIQUE
);

CREATE TABLE cve_tecnologias (
    cve_id         INTEGER NOT NULL REFERENCES cves(id)        ON DELETE CASCADE,
    tecnologia_id  INTEGER NOT NULL REFERENCES tecnologias(id) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, tecnologia_id)
);

-- -------------------------------------------------------------
-- Notas de mitigação escritas pelo time
-- -------------------------------------------------------------
CREATE TABLE notas (
    id          SERIAL PRIMARY KEY,
    cve_id      INTEGER NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    usuario_id  INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
    texto       TEXT    NOT NULL,
    criado_em   TIMESTAMP NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------------
-- Referências externas: exploits/PoCs públicos e avisos (vêm do Telegram)
-- -------------------------------------------------------------
CREATE TABLE referencias (
    id         SERIAL PRIMARY KEY,
    cve_id     INTEGER NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    tipo       VARCHAR(10) NOT NULL CHECK (tipo IN ('poc', 'advisory', 'outro')),
    url        TEXT NOT NULL,
    criado_em  TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (cve_id, url)
);

-- =============================================================
-- Extra de segurança: honeypot
-- =============================================================

-- Iscas: uma CVE inteira ou uma nota de mitigação falsa.
-- Para o usuário comum elas aparecem como qualquer outro registro.
CREATE TABLE honeypots (
    id         SERIAL PRIMARY KEY,
    tipo       VARCHAR(10) NOT NULL CHECK (tipo IN ('cve', 'nota')),
    cve_id     INTEGER REFERENCES cves(id)  ON DELETE CASCADE,
    nota_id    INTEGER REFERENCES notas(id) ON DELETE CASCADE,
    descricao  TEXT,
    ativo      BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em  TIMESTAMP NOT NULL DEFAULT NOW(),
    CHECK ((tipo = 'cve'  AND cve_id  IS NOT NULL AND nota_id IS NULL) OR
           (tipo = 'nota' AND nota_id IS NOT NULL AND cve_id  IS NULL))
);

-- Termos de busca que indicam alguém tentando contornar mitigações
CREATE TABLE termos_suspeitos (
    id     SERIAL PRIMARY KEY,
    termo  VARCHAR(60) NOT NULL UNIQUE
);

-- Trilha de auditoria: quem abriu qual CVE / nota
CREATE TABLE log_acessos (
    id          SERIAL PRIMARY KEY,
    usuario_id  INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
    cve_id      INTEGER REFERENCES cves(id)  ON DELETE SET NULL,
    nota_id     INTEGER REFERENCES notas(id) ON DELETE SET NULL,
    criado_em   TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Alertas gerados quando alguém morde uma isca ou faz busca suspeita
CREATE TABLE alertas_seguranca (
    id           SERIAL PRIMARY KEY,
    usuario_id   INTEGER REFERENCES usuarios(id)  ON DELETE SET NULL,
    honeypot_id  INTEGER REFERENCES honeypots(id) ON DELETE SET NULL,
    motivo       VARCHAR(20) NOT NULL CHECK (motivo IN ('isca_cve', 'isca_nota', 'busca_suspeita', 'volume')),
    termo_busca  TEXT,
    criado_em    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_log_usuario_data ON log_acessos (usuario_id, criado_em);
