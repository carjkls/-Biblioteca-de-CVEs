# 🛡️ Biblioteca de CVEs

Sistema web para o time de desenvolvimento consultar vulnerabilidades conhecidas (CVEs) enquanto programa. Cada CVE tem CVSS, severidade, tecnologias afetadas, links de **exploits públicos** e **notas de mitigação** escritas pelo próprio time ("atualizamos para a versão X", "rodem tal comando no build"). As CVEs podem ser importadas direto do Telegram (por exemplo, do canal CVE Monitor, t.me/cvedetector).

Trabalho prático de Banco de Dados (CRUD com PostgreSQL), com um extra de segurança: um **honeypot** que detecta quem tenta descobrir como o time mitigou falhas para contorná-las.

## Funcionalidades

| Requisito do trabalho | Onde está |
|---|---|
| Login de usuário | Tela inicial. Senha guardada com bcrypt (`pgcrypto`), conferida no próprio SQL. Perfis `admin` e `dev`. |
| CRUD | CVEs (cadastrar, consultar, editar, excluir), notas de mitigação, usuários e iscas do honeypot. |
| Tabelas relacionadas (FK) | 10 tabelas, incluindo relação N:N entre `cves` e `tecnologias`. Ver diagrama abaixo. |
| Filtros com SQL | Busca por texto (`ILIKE`), severidade, faixa de CVSS, ano, tecnologia, origem e "só com exploit público", todos combináveis. |
| Comandos SQL | Pasta [`sql/`](sql/): `01_schema.sql`, `02_seed.sql`, `03_consultas.sql`. O código usa SQL puro, sem ORM. |
| Interface gráfica (bônus) | Streamlit. |

O que cada perfil vê:

- **dev**: Biblioteca (com filtros), detalhe da CVE, notas de mitigação (pode criar e editar as próprias), Relatórios.
- **admin**: tudo do dev, mais Cadastrar CVE, editar/excluir CVE, Importar Telegram, Honeypot e Usuários.

## Tecnologias

- Python 3.11+
- Streamlit (interface)
- PostgreSQL 16 + extensão `pgcrypto`
- psycopg 3 (driver, SQL escrito à mão)
- pandas (tabelas na tela)
- Docker Compose (opcional, para subir o banco)

## Modelo de dados

```
usuarios ──< cves >──< cve_tecnologias >── tecnologias
   │          │
   │          ├──< notas
   │          └──< referencias (exploits/PoCs públicos)
   │                 │
   ├──< log_acessos ─┘ (cve_id, nota_id)
   │
   └──< alertas_seguranca >── honeypots ──> cves | notas

termos_suspeitos (lista de palavras usada pelo honeypot)
```

| Tabela | Para quê | Chaves estrangeiras |
|---|---|---|
| `usuarios` | Login e perfil | |
| `cves` | Tabela principal. `severidade` é coluna gerada a partir do `cvss` | `criado_por → usuarios` |
| `tecnologias` | Node.js, OpenSSL, Log4j... | |
| `cve_tecnologias` | Relação N:N | `cve_id → cves`, `tecnologia_id → tecnologias` |
| `notas` | Como o time mitigou cada CVE | `cve_id → cves`, `usuario_id → usuarios` |
| `referencias` | Links de exploit público (PoC) e avisos | `cve_id → cves` |
| `honeypots` | Iscas (CVE inteira ou nota falsa) | `cve_id → cves`, `nota_id → notas` |
| `termos_suspeitos` | Palavras que disparam alerta na busca | |
| `log_acessos` | Auditoria de quem abriu o quê | `usuario_id`, `cve_id`, `nota_id` |
| `alertas_seguranca` | Alertas do honeypot | `usuario_id → usuarios`, `honeypot_id → honeypots` |

Regras de exclusão: apagar uma CVE apaga suas notas, vínculos e iscas (`ON DELETE CASCADE`). Apagar um usuário mantém as CVEs e notas dele, só zera o autor (`ON DELETE SET NULL`).

## Como executar

### 1. Banco de dados

**Opção A: Docker (mais fácil).** Cria o banco e já roda o schema e os dados de teste:

```bash
docker compose up -d
```

**Opção B: PostgreSQL instalado na máquina.**

```bash
createdb -U postgres biblioteca_cves
psql -U postgres -d biblioteca_cves -f sql/01_schema.sql
psql -U postgres -d biblioteca_cves -f sql/02_seed.sql
```

Por padrão o sistema conecta em `postgresql://postgres:postgres@localhost:5432/biblioteca_cves`. Para mudar, defina a variável `DATABASE_URL`:

```bash
export DATABASE_URL="postgresql://usuario:senha@host:5432/biblioteca_cves"   # Linux/macOS
set DATABASE_URL=postgresql://usuario:senha@host:5432/biblioteca_cves        # Windows
```

### 2. Aplicação

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app/main.py
```

Abra http://localhost:8501.

## Usuários para teste

| Perfil | E-mail | Senha |
|---|---|---|
| admin | `admin@cves.local` | `admin123` |
| dev | `dev@cves.local` | `dev123` |
| dev | `maria@cves.local` | `dev123` |

## Importar CVEs do Telegram

Entre como admin → **Importar Telegram**. Dá para importar de dois jeitos:

- **Colar mensagens**: selecione as mensagens no Telegram, copie e cole na caixa de texto. O jeito mais rápido.
- **Arquivo JSON**: no Telegram Desktop, abra o chat → ⋮ → **Exportar histórico do chat** → desmarque mídias → formato **JSON**, e envie o `result.json`. Melhor para importar o histórico inteiro.

A tela mostra uma prévia antes de gravar. Pelo terminal também funciona, com `.json` ou `.txt`:

```bash
python scripts/importar_telegram.py exemplos/telegram_cvedetector.txt
python scripts/importar_telegram.py caminho/para/result.json
```

O importador entende o formato do canal **CVE Monitor** (t.me/cvedetector):

| Na mensagem | Vira |
|---|---|
| `"Title": "CVE-2026-114196 - WordPress Paytium plugin ..."` | código e título |
| `Description : ...` | descrição |
| `Severity: 9.8 \| CRITICAL` (ou `CVSS: 9.8`, `scores 3.3`) | CVSS, e a severidade é calculada pelo banco |
| `Published : Oct. 24, 2026` | data de publicação |
| `"Type": "Exploit POC"` + `"Source": "https://github.com/..."` | link de exploit público na tabela `referencias` |
| nomes como WordPress, PHP, MongoDB, Node.js | vínculo com a tecnologia cadastrada |

Mensagens fora desse padrão também funcionam: qualquer `CVE-AAAA-NNNN` citada vira registro, com o texto como descrição. Reimportar não duplica: se a CVE já existe, o banco só completa o que estava vazio (`INSERT ... ON CONFLICT (codigo) DO UPDATE SET cvss = COALESCE(...)`), e links de PoC repetidos são ignorados (`UNIQUE (cve_id, url)`).

Exemplos reais em [`exemplos/telegram_cvedetector.txt`](exemplos/telegram_cvedetector.txt) (mensagens do CVE Monitor) e [`exemplos/telegram_exemplo.json`](exemplos/telegram_exemplo.json) (formato da exportação JSON).

## 🍯 Honeypot (extra de segurança)

**A ameaça.** Uma biblioteca de mitigações também é um mapa para o atacante: alguém com acesso (conta roubada ou alguém de dentro) pode procurar como o time corrigiu uma falha justamente para achar o ponto que ficou de fora e contornar a correção.

**A defesa.** O sistema planta iscas exatamente nesse caminho. Nenhum uso legítimo leva até elas, então qualquer interação é um sinal forte.

- **CVE isca**: um aviso interno falso com título atraente, por exemplo `INT-2026-014 · Bypass do WAF interno no gateway de pagamentos (sem patch)`.
- **Nota de mitigação isca**: uma nota falsa pendurada numa CVE real, com "detalhes internos" e uma credencial falsa (honeytoken, ex.: `svc-scan`). Se essa credencial aparecer num log de login real, também denuncia o vazamento.
- **Busca suspeita**: pesquisar termos como `bypass`, `contornar`, `burlar`, `evadir`, `sem patch`, `credencial` gera alerta. A lista fica na tabela `termos_suspeitos` e pode ser editada.
- **Volume anormal**: abrir mais de 8 notas de mitigação em 10 minutos gera alerta (padrão de quem está raspando a base).

Para o dev, as iscas parecem registros comuns. As notas de mitigação ficam fechadas atrás de um botão "Ver mitigação", e cada abertura vai para `log_acessos`. Só usuários `dev` geram alertas, porque é o admin quem planta as iscas. No menu **Honeypot**, o admin vê os alertas (quem, quando, qual isca, qual termo), o ranking de usuários suspeitos e pode criar, desativar e excluir iscas. Na Biblioteca, as iscas aparecem com 🍯 só para o admin.

**Para testar:**

1. Entre como `dev@cves.local`, busque `bypass`, abra `INT-2026-014` e clique em "Ver mitigação".
2. Abra `CVE-2021-44228` e veja as notas.
3. Saia, entre como `admin@cves.local` e abra **Honeypot → Alertas**.

## Estrutura do projeto

```
biblioteca-cves/
├── app/
│   ├── main.py              # telas Streamlit
│   ├── db.py                # conexão e todo o SQL do CRUD, filtros e relatórios
│   ├── honeypot.py          # iscas, auditoria e alertas
│   └── telegram_import.py   # leitura das mensagens do Telegram (texto colado ou JSON)
├── scripts/
│   └── importar_telegram.py # importação pelo terminal
├── sql/
│   ├── 01_schema.sql        # CREATE TABLE, FKs, índices
│   ├── 02_seed.sql          # usuários, tecnologias, CVEs reais e iscas
│   └── 03_consultas.sql     # principais consultas do sistema, prontas para o psql
├── exemplos/
│   ├── telegram_cvedetector.txt
│   └── telegram_exemplo.json
├── docker-compose.yml
└── requirements.txt
```
