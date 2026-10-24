-- =============================================================
-- Biblioteca de CVEs - Dados iniciais para teste
-- =============================================================
-- Execute depois do schema: psql -U postgres -d biblioteca_cves -f sql/02_seed.sql

-- Usuários de teste (senhas com bcrypt via pgcrypto)
--   admin@cves.local / admin123  (papel admin)
--   dev@cves.local   / dev123    (papel dev)
INSERT INTO usuarios (nome, email, senha_hash, papel) VALUES
    ('Administrador', 'admin@cves.local', crypt('admin123', gen_salt('bf')), 'admin'),
    ('Dev Teste',     'dev@cves.local',   crypt('dev123',   gen_salt('bf')), 'dev'),
    ('Maria Backend', 'maria@cves.local', crypt('dev123',   gen_salt('bf')), 'dev');

INSERT INTO tecnologias (nome) VALUES
    ('Java'), ('Log4j'), ('Spring'), ('Apache Struts'), ('OpenSSL'), ('Linux'),
    ('OpenSSH'), ('xz/liblzma'), ('HTTP/2'), ('Node.js'), ('lodash'), ('jQuery'),
    ('libwebp'), ('Chrome'), ('Nginx'), ('Python'), ('PostgreSQL'), ('Docker'),
    ('WordPress'), ('PHP'), ('MongoDB'), ('Electron'), ('Brotli'), ('SQLite'), ('Windows'), ('Jira');

INSERT INTO cves (codigo, titulo, descricao, cvss, data_publicacao, link_referencia, criado_por) VALUES
    ('CVE-2021-44228', 'Log4Shell: RCE via JNDI no Log4j 2',
     'Entradas controladas pelo atacante e registradas pelo Log4j podem disparar lookup JNDI e executar código remoto.',
     10.0, '2021-12-10', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228', 1),
    ('CVE-2024-3094', 'Backdoor no xz/liblzma',
     'Código malicioso inserido nos tarballs do xz 5.6.0 e 5.6.1 permite comprometer o sshd em algumas distros.',
     10.0, '2024-03-29', 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094', 1),
    ('CVE-2014-0160', 'Heartbleed: vazamento de memória no OpenSSL',
     'Falha na extensão heartbeat do TLS permite ler até 64KB de memória do servidor por requisição.',
     7.5, '2014-04-07', 'https://nvd.nist.gov/vuln/detail/CVE-2014-0160', 1),
    ('CVE-2023-44487', 'HTTP/2 Rapid Reset (DoS)',
     'Abertura e cancelamento rápido de streams HTTP/2 causa negação de serviço em servidores.',
     7.5, '2023-10-10', 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487', 1),
    ('CVE-2022-22965', 'Spring4Shell: RCE via data binding',
     'Aplicações Spring MVC/WebFlux em JDK 9+ podem sofrer execução remota de código via data binding.',
     9.8, '2022-03-31', 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965', 1),
    ('CVE-2017-5638', 'RCE no Apache Struts via Content-Type',
     'O parser Jakarta Multipart trata mal o cabeçalho Content-Type e permite execução de comandos.',
     10.0, '2017-03-10', 'https://nvd.nist.gov/vuln/detail/CVE-2017-5638', 1),
    ('CVE-2021-23337', 'Injeção de comando no lodash template',
     'A função template do lodash antes da 4.17.21 permite injeção de comandos.',
     7.2, '2021-02-15', 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337', 1),
    ('CVE-2019-11358', 'Prototype pollution no jQuery',
     'jQuery antes da 3.4.0 trata mal jQuery.extend(true, {}, ...) e permite poluir Object.prototype.',
     6.1, '2019-04-20', 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358', 1),
    ('CVE-2023-4863', 'Heap overflow no libwebp',
     'Estouro de heap ao processar imagens WebP, explorado ativamente via navegadores.',
     8.8, '2023-09-12', 'https://nvd.nist.gov/vuln/detail/CVE-2023-4863', 1),
    ('CVE-2024-6387', 'regreSSHion: RCE no OpenSSH',
     'Condição de corrida no tratamento de sinais do sshd permite execução remota como root em glibc Linux.',
     8.1, '2024-07-01', 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387', 1),
    -- Isca (honeypot): aviso interno falso, com título atraente para quem procura brecha
    ('INT-2026-014', 'Bypass do WAF interno no gateway de pagamentos (sem patch)',
     'Aviso interno: regra do WAF pode ser contornada em rotas legadas. Detalhes de mitigação nas notas.',
     9.1, '2026-09-02', NULL, 1);

INSERT INTO cve_tecnologias (cve_id, tecnologia_id)
SELECT c.id, t.id FROM cves c JOIN tecnologias t ON (c.codigo, t.nome) IN (
    ('CVE-2021-44228', 'Java'), ('CVE-2021-44228', 'Log4j'),
    ('CVE-2024-3094', 'xz/liblzma'), ('CVE-2024-3094', 'Linux'), ('CVE-2024-3094', 'OpenSSH'),
    ('CVE-2014-0160', 'OpenSSL'),
    ('CVE-2023-44487', 'HTTP/2'), ('CVE-2023-44487', 'Nginx'),
    ('CVE-2022-22965', 'Java'), ('CVE-2022-22965', 'Spring'),
    ('CVE-2017-5638', 'Java'), ('CVE-2017-5638', 'Apache Struts'),
    ('CVE-2021-23337', 'Node.js'), ('CVE-2021-23337', 'lodash'),
    ('CVE-2019-11358', 'jQuery'),
    ('CVE-2023-4863', 'libwebp'), ('CVE-2023-4863', 'Chrome'),
    ('CVE-2024-6387', 'OpenSSH'), ('CVE-2024-6387', 'Linux'),
    ('INT-2026-014', 'Nginx')
);

INSERT INTO notas (cve_id, usuario_id, texto)
SELECT c.id, n.usuario_id, n.texto
FROM (VALUES
    ('CVE-2021-44228', 2, 'Atualizamos o Log4j para 2.17.1 em todos os serviços Java e removemos JndiLookup.class das imagens antigas.'),
    ('CVE-2021-44228', 3, 'Verifiquem dependências transitivas com: mvn dependency:tree | grep log4j'),
    ('CVE-2024-3094',  2, 'Pipeline de imagens fixado em xz 5.4.6. Rodar "xz --version" no build para garantir.'),
    ('CVE-2014-0160',  3, 'Todas as bases usam OpenSSL 3.x. Certificados antigos foram revogados e reemitidos.'),
    ('CVE-2023-44487', 2, 'Nginx atualizado para 1.25.3 e limite de streams concorrentes configurado (http2_max_concurrent_streams 64).'),
    ('CVE-2021-23337', 3, 'lodash >= 4.17.21 forçado via "overrides" no package.json.'),
    -- Isca (honeypot): nota falsa com "detalhes internos" e uma credencial falsa (honeytoken)
    ('CVE-2021-44228', 1, 'Exceção temporária: rota /api/legacy ainda fora do WAF. Conta de serviço para varredura: svc-scan / Hp-Isca-2026!'),
    ('INT-2026-014',   1, 'Enquanto não sai o patch, o tráfego com header X-Internal-Debug: 1 passa direto pelo WAF.')
) AS n(codigo, usuario_id, texto)
JOIN cves c ON c.codigo = n.codigo;

-- Registra as iscas
INSERT INTO honeypots (tipo, cve_id, descricao)
SELECT 'cve', id, 'Aviso interno falso de bypass do WAF' FROM cves WHERE codigo = 'INT-2026-014';

INSERT INTO honeypots (tipo, nota_id, descricao)
SELECT 'nota', id, 'Nota falsa com honeytoken svc-scan' FROM notas WHERE texto LIKE '%svc-scan%';

INSERT INTO honeypots (tipo, nota_id, descricao)
SELECT 'nota', id, 'Nota falsa com header de bypass' FROM notas WHERE texto LIKE '%X-Internal-Debug%';

INSERT INTO termos_suspeitos (termo) VALUES
    ('bypass'), ('contornar'), ('burlar'), ('evadir'), ('evasion'),
    ('desativar mitigação'), ('desabilitar waf'), ('sem patch'), ('credencial'), ('senha');

-- Exploits públicos conhecidos (no uso real vêm das mensagens "Exploit POC" do Telegram)
INSERT INTO referencias (cve_id, tipo, url)
SELECT c.id, 'poc', r.url
FROM (VALUES
    ('CVE-2021-44228', 'https://github.com/kozmer/log4j-shell-poc'),
    ('CVE-2014-0160',  'https://github.com/sensepost/heartbleed-poc')
) AS r(codigo, url)
JOIN cves c ON c.codigo = r.codigo;
