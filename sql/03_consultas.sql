-- =============================================================
-- Biblioteca de CVEs - Principais consultas usadas no sistema
-- =============================================================
-- No código (app/db.py e app/honeypot.py) os valores entram como parâmetros (%s),
-- aqui estão com valores de exemplo para rodar direto no psql.

-- -------------------------------------------------------------
-- 1. LOGIN: compara a senha com o hash bcrypt (pgcrypto)
-- -------------------------------------------------------------
SELECT id, nome, email, papel
  FROM usuarios
 WHERE email = 'dev@cves.local'
   AND ativo
   AND senha_hash = crypt('dev123', senha_hash);

-- -------------------------------------------------------------
-- 2. CRUD de CVEs
-- -------------------------------------------------------------
-- Cadastrar (ignora se o código já existir)
INSERT INTO cves (codigo, titulo, descricao, cvss, data_publicacao, link_referencia, criado_por)
VALUES ('CVE-2025-0001', 'Exemplo de cadastro', 'Descrição de teste', 6.5, '2025-01-15', NULL, 1)
ON CONFLICT (codigo) DO NOTHING
RETURNING id;

-- Vincular tecnologias (tabela N:N)
INSERT INTO cve_tecnologias (cve_id, tecnologia_id)
SELECT c.id, t.id FROM cves c, tecnologias t
 WHERE c.codigo = 'CVE-2025-0001' AND t.nome = 'Python'
ON CONFLICT DO NOTHING;

-- Consultar uma CVE com quem cadastrou (JOIN com usuarios)
SELECT c.*, u.nome AS criado_por_nome
  FROM cves c
  LEFT JOIN usuarios u ON u.id = c.criado_por
 WHERE c.codigo = 'CVE-2025-0001';

-- Atualizar
UPDATE cves
   SET titulo = 'Exemplo atualizado', cvss = 9.3, atualizado_em = NOW()
 WHERE codigo = 'CVE-2025-0001';
-- (a severidade muda sozinha para 'critica': é uma coluna gerada a partir do CVSS)

-- Excluir (notas, vínculos e iscas saem junto por ON DELETE CASCADE)
DELETE FROM cves WHERE codigo = 'CVE-2025-0001';

-- -------------------------------------------------------------
-- 3. FILTROS da tela Biblioteca (todos combináveis)
-- -------------------------------------------------------------
SELECT c.id, c.codigo, c.titulo, c.cvss, c.severidade, c.data_publicacao, c.origem,
       COALESCE(STRING_AGG(t.nome, ', ' ORDER BY t.nome), '') AS tecnologias,
       (SELECT COUNT(*) FROM notas n WHERE n.cve_id = c.id)   AS qtd_notas
  FROM cves c
  LEFT JOIN cve_tecnologias ct ON ct.cve_id = c.id
  LEFT JOIN tecnologias t      ON t.id = ct.tecnologia_id
 WHERE COALESCE(c.cvss, 0) BETWEEN 7.0 AND 10.0                        -- faixa de CVSS
   AND (c.codigo ILIKE '%ssh%' OR c.titulo ILIKE '%ssh%'
        OR c.descricao ILIKE '%ssh%')                                  -- busca por texto
   AND c.severidade = ANY(ARRAY['critica', 'alta'])                    -- severidades
   AND EXTRACT(YEAR FROM c.data_publicacao) = 2024                     -- ano
   AND EXISTS (SELECT 1 FROM cve_tecnologias x
                JOIN tecnologias tx ON tx.id = x.tecnologia_id
               WHERE x.cve_id = c.id AND tx.nome = 'OpenSSH')          -- tecnologia
 GROUP BY c.id
 ORDER BY c.cvss DESC NULLS LAST, c.data_publicacao DESC NULLS LAST;

-- Tecnologias de uma CVE
SELECT t.id, t.nome
  FROM tecnologias t
  JOIN cve_tecnologias ct ON ct.tecnologia_id = t.id
  JOIN cves c             ON c.id = ct.cve_id
 WHERE c.codigo = 'CVE-2021-44228'
 ORDER BY t.nome;

-- -------------------------------------------------------------
-- 4. NOTAS de mitigação (CRUD)
-- -------------------------------------------------------------
SELECT n.id, n.texto, n.criado_em, u.nome AS autor
  FROM notas n
  LEFT JOIN usuarios u ON u.id = n.usuario_id
  JOIN cves c          ON c.id = n.cve_id
 WHERE c.codigo = 'CVE-2021-44228'
 ORDER BY n.criado_em, n.id;

INSERT INTO notas (cve_id, usuario_id, texto)
SELECT id, 2, 'Nota de exemplo' FROM cves WHERE codigo = 'CVE-2014-0160';
UPDATE notas SET texto = 'Nota de exemplo (editada)' WHERE texto = 'Nota de exemplo';
DELETE FROM notas WHERE texto = 'Nota de exemplo (editada)';

-- -------------------------------------------------------------
-- 5. RELATÓRIOS
-- -------------------------------------------------------------
-- Quantidade e CVSS médio por severidade
SELECT severidade, COUNT(*) AS total, ROUND(AVG(cvss), 1) AS cvss_medio
  FROM cves
 GROUP BY severidade
 ORDER BY MAX(COALESCE(cvss, -1)) DESC;

-- CVEs por tecnologia, com quantas são críticas
SELECT t.nome AS tecnologia, COUNT(ct.cve_id) AS total,
       COUNT(*) FILTER (WHERE c.severidade = 'critica') AS criticas
  FROM tecnologias t
  JOIN cve_tecnologias ct ON ct.tecnologia_id = t.id
  JOIN cves c             ON c.id = ct.cve_id
 GROUP BY t.nome
HAVING COUNT(ct.cve_id) > 0
 ORDER BY total DESC, t.nome;

-- CVEs mais comentadas pelo time
SELECT c.codigo, c.titulo, COUNT(n.id) AS notas
  FROM cves c
  JOIN notas n ON n.cve_id = c.id
 GROUP BY c.id
 ORDER BY notas DESC, c.codigo
 LIMIT 10;

-- CVEs que ninguém documentou como mitigar ainda (LEFT JOIN + IS NULL)
SELECT c.codigo, c.titulo, c.severidade
  FROM cves c
  LEFT JOIN notas n ON n.cve_id = c.id
 WHERE n.id IS NULL
 ORDER BY c.cvss DESC NULLS LAST;

-- CVEs com exploit público, as sem nota de mitigação primeiro (as mais urgentes)
SELECT c.codigo, c.titulo, c.severidade, COUNT(DISTINCT r.id) AS pocs,
       COUNT(DISTINCT n.id) AS notas
  FROM cves c
  JOIN referencias r ON r.cve_id = c.id AND r.tipo = 'poc'
  LEFT JOIN notas n  ON n.cve_id = c.id
 GROUP BY c.id
 ORDER BY (COUNT(DISTINCT n.id) = 0) DESC, pocs DESC;

-- Filtro "só com exploit público"
SELECT c.codigo, c.titulo
  FROM cves c
 WHERE EXISTS (SELECT 1 FROM referencias r WHERE r.cve_id = c.id AND r.tipo = 'poc');

-- -------------------------------------------------------------
-- 6. IMPORTAÇÃO DO TELEGRAM
-- -------------------------------------------------------------
-- Upsert: cria a CVE ou só completa o que estava vazio. xmax = 0 indica linha recém-inserida.
INSERT INTO cves (codigo, titulo, descricao, cvss, data_publicacao, link_referencia,
                  origem, telegram_msg_id, criado_por)
VALUES ('CVE-2026-114196', 'WordPress Paytium plugin <= 5.0.5 - php object injection vulnerability',
        'Deserialization of Untrusted Data vulnerability in Paytium ...', 9.8, '2026-10-24',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-114196', 'telegram', NULL, 1)
ON CONFLICT (codigo) DO UPDATE
   SET cvss            = COALESCE(cves.cvss, EXCLUDED.cvss),
       descricao       = COALESCE(cves.descricao, EXCLUDED.descricao),
       data_publicacao = COALESCE(cves.data_publicacao, EXCLUDED.data_publicacao),
       link_referencia = COALESCE(cves.link_referencia, EXCLUDED.link_referencia)
RETURNING id, (xmax = 0) AS inserida;

-- Mensagem "Exploit POC": guarda o link do exploit (repetido é ignorado)
INSERT INTO referencias (cve_id, tipo, url)
SELECT id, 'poc', 'https://github.com/exemplo/poc' FROM cves WHERE codigo = 'CVE-2026-114196'
ON CONFLICT DO NOTHING;

SELECT origem, COUNT(*) FROM cves GROUP BY origem;

-- -------------------------------------------------------------
-- 7. HONEYPOT
-- -------------------------------------------------------------
-- A CVE aberta é uma isca ativa?
SELECT id FROM honeypots WHERE cve_id = 11 AND ativo;

-- A busca contém algum termo suspeito?
SELECT termo FROM termos_suspeitos
 WHERE 'como fazer bypass do waf' ILIKE '%' || termo || '%'
 LIMIT 1;

-- Registrar acesso e alerta
INSERT INTO log_acessos (usuario_id, cve_id) VALUES (2, 11);
INSERT INTO alertas_seguranca (usuario_id, honeypot_id, motivo) VALUES (2, 1, 'isca_cve');

-- Quantas notas o usuário abriu nos últimos 10 minutos (alerta de volume)
SELECT COUNT(*) AS total
  FROM log_acessos
 WHERE usuario_id = 2
   AND nota_id IS NOT NULL
   AND criado_em > NOW() - make_interval(mins => 10);

-- Painel: alertas com usuário e isca (2 LEFT JOINs)
SELECT a.criado_em AS quando, u.nome AS usuario, u.email, a.motivo,
       h.descricao AS isca, a.termo_busca
  FROM alertas_seguranca a
  LEFT JOIN usuarios u  ON u.id = a.usuario_id
  LEFT JOIN honeypots h ON h.id = a.honeypot_id
 ORDER BY a.criado_em DESC;

-- Iscas com a CVE de origem e quantos alertas cada uma gerou
SELECT h.id, h.tipo, h.descricao, h.ativo,
       COALESCE(c.codigo, cn.codigo) AS cve,
       LEFT(n.texto, 80)             AS nota,
       COUNT(a.id)                   AS alertas
  FROM honeypots h
  LEFT JOIN cves c   ON c.id = h.cve_id
  LEFT JOIN notas n  ON n.id = h.nota_id
  LEFT JOIN cves cn  ON cn.id = n.cve_id
  LEFT JOIN alertas_seguranca a ON a.honeypot_id = h.id
 GROUP BY h.id, c.codigo, cn.codigo, n.texto
 ORDER BY h.id;

-- Ranking de usuários suspeitos
SELECT u.nome, u.email, COUNT(*) AS alertas, MAX(a.criado_em) AS ultimo
  FROM alertas_seguranca a
  JOIN usuarios u ON u.id = a.usuario_id
 GROUP BY u.id
 ORDER BY alertas DESC;
