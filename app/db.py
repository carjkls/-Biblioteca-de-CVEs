"""Acesso ao PostgreSQL. Todo o SQL do sistema fica aqui, escrito à mão (sem ORM)."""
import os

import psycopg
from psycopg.rows import dict_row

DSN = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/biblioteca_cves",
)


def conectar():
    return psycopg.connect(DSN, row_factory=dict_row)


def consultar(sql, params=None):
    with conectar() as conn:
        return conn.execute(sql, params).fetchall()


def consultar_um(sql, params=None):
    with conectar() as conn:
        return conn.execute(sql, params).fetchone()


def executar(sql, params=None):
    with conectar() as conn:
        cur = conn.execute(sql, params)
        return cur.fetchone() if cur.description else None


# ------------------------------------------------------------------ login

def autenticar(email, senha):
    # crypt(senha, hash) recalcula o bcrypt com o mesmo salt e compara
    return consultar_um(
        """
        SELECT id, nome, email, papel
          FROM usuarios
         WHERE email = %s
           AND ativo
           AND senha_hash = crypt(%s, senha_hash)
        """,
        (email, senha),
    )


# ------------------------------------------------------------------ tecnologias

def listar_tecnologias():
    return consultar("SELECT id, nome FROM tecnologias ORDER BY nome")


def criar_tecnologia(nome):
    return executar(
        "INSERT INTO tecnologias (nome) VALUES (%s) ON CONFLICT (nome) DO UPDATE SET nome = EXCLUDED.nome RETURNING id",
        (nome.strip(),),
    )["id"]


# ------------------------------------------------------------------ CVEs: consulta com filtros

def buscar_cves(texto=None, severidades=None, cvss_min=0.0, cvss_max=10.0,
                ano=None, tecnologia_id=None, origem=None, so_com_exploit=False):
    filtros = ["COALESCE(c.cvss, 0) BETWEEN %(cvss_min)s AND %(cvss_max)s"]
    params = {"cvss_min": cvss_min, "cvss_max": cvss_max}

    if texto:
        filtros.append("(c.codigo ILIKE %(texto)s OR c.titulo ILIKE %(texto)s OR c.descricao ILIKE %(texto)s)")
        params["texto"] = f"%{texto}%"
    if severidades:
        filtros.append("c.severidade = ANY(%(severidades)s)")
        params["severidades"] = list(severidades)
    if ano:
        filtros.append("EXTRACT(YEAR FROM c.data_publicacao) = %(ano)s")
        params["ano"] = ano
    if tecnologia_id:
        filtros.append(
            "EXISTS (SELECT 1 FROM cve_tecnologias ct WHERE ct.cve_id = c.id AND ct.tecnologia_id = %(tec)s)"
        )
        params["tec"] = tecnologia_id
    if origem:
        filtros.append("c.origem = %(origem)s")
        params["origem"] = origem
    if so_com_exploit:
        filtros.append("EXISTS (SELECT 1 FROM referencias r WHERE r.cve_id = c.id AND r.tipo = 'poc')")

    sql = f"""
        SELECT c.id, c.codigo, c.titulo, c.cvss, c.severidade, c.data_publicacao, c.origem,
               COALESCE(STRING_AGG(t.nome, ', ' ORDER BY t.nome), '') AS tecnologias,
               (SELECT COUNT(*) FROM notas n WHERE n.cve_id = c.id) AS qtd_notas,
               (SELECT COUNT(*) FROM referencias r WHERE r.cve_id = c.id AND r.tipo = 'poc') AS qtd_pocs
          FROM cves c
          LEFT JOIN cve_tecnologias ct ON ct.cve_id = c.id
          LEFT JOIN tecnologias t      ON t.id = ct.tecnologia_id
         WHERE {' AND '.join(filtros)}
         GROUP BY c.id
         ORDER BY c.cvss DESC NULLS LAST, c.data_publicacao DESC NULLS LAST
    """
    return consultar(sql, params)


def anos_disponiveis():
    rows = consultar(
        "SELECT DISTINCT EXTRACT(YEAR FROM data_publicacao)::int AS ano FROM cves "
        "WHERE data_publicacao IS NOT NULL ORDER BY ano DESC"
    )
    return [r["ano"] for r in rows]


def obter_cve(cve_id):
    return consultar_um(
        """
        SELECT c.*, u.nome AS criado_por_nome
          FROM cves c
          LEFT JOIN usuarios u ON u.id = c.criado_por
         WHERE c.id = %s
        """,
        (cve_id,),
    )


def tecnologias_da_cve(cve_id):
    return consultar(
        """
        SELECT t.id, t.nome
          FROM tecnologias t
          JOIN cve_tecnologias ct ON ct.tecnologia_id = t.id
         WHERE ct.cve_id = %s
         ORDER BY t.nome
        """,
        (cve_id,),
    )


# ------------------------------------------------------------------ CVEs: cadastrar / atualizar / excluir

def criar_cve(codigo, titulo, descricao, cvss, data_publicacao, link, tecnologia_ids, usuario_id,
              origem="manual", telegram_msg_id=None):
    with conectar() as conn:
        row = conn.execute(
            """
            INSERT INTO cves (codigo, titulo, descricao, cvss, data_publicacao, link_referencia,
                              origem, telegram_msg_id, criado_por)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (codigo) DO NOTHING
            RETURNING id
            """,
            (codigo.upper().strip(), titulo, descricao, cvss, data_publicacao, link,
             origem, telegram_msg_id, usuario_id),
        ).fetchone()
        if row is None:
            return None
        _gravar_tecnologias(conn, row["id"], tecnologia_ids)
        return row["id"]


def atualizar_cve(cve_id, codigo, titulo, descricao, cvss, data_publicacao, link, tecnologia_ids):
    with conectar() as conn:
        conn.execute(
            """
            UPDATE cves
               SET codigo = %s, titulo = %s, descricao = %s, cvss = %s,
                   data_publicacao = %s, link_referencia = %s, atualizado_em = NOW()
             WHERE id = %s
            """,
            (codigo.upper().strip(), titulo, descricao, cvss, data_publicacao, link, cve_id),
        )
        conn.execute("DELETE FROM cve_tecnologias WHERE cve_id = %s", (cve_id,))
        _gravar_tecnologias(conn, cve_id, tecnologia_ids)


def _gravar_tecnologias(conn, cve_id, tecnologia_ids):
    for tec_id in tecnologia_ids or []:
        conn.execute(
            "INSERT INTO cve_tecnologias (cve_id, tecnologia_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (cve_id, tec_id),
        )


def importar_cve(cve, usuario_id):
    """Upsert vindo do Telegram: cria a CVE ou completa campos vazios de uma que já existe.
    xmax = 0 só é verdade para a linha recém-inserida; devolve (id, inserida)."""
    with conectar() as conn:
        row = conn.execute(
            """
            INSERT INTO cves (codigo, titulo, descricao, cvss, data_publicacao, link_referencia,
                              origem, telegram_msg_id, criado_por)
            VALUES (%s, %s, %s, %s, %s, %s, 'telegram', %s, %s)
            ON CONFLICT (codigo) DO UPDATE
               SET cvss            = COALESCE(cves.cvss, EXCLUDED.cvss),
                   descricao       = COALESCE(cves.descricao, EXCLUDED.descricao),
                   data_publicacao = COALESCE(cves.data_publicacao, EXCLUDED.data_publicacao),
                   link_referencia = COALESCE(cves.link_referencia, EXCLUDED.link_referencia)
            RETURNING id, (xmax = 0) AS inserida
            """,
            (cve["codigo"], cve["titulo"], cve["descricao"], cve["cvss"], cve["data_publicacao"],
             cve["link"], cve["telegram_msg_id"], usuario_id),
        ).fetchone()
        _gravar_tecnologias(conn, row["id"], cve["tecnologia_ids"])
        return row["id"], row["inserida"]


def excluir_cve(cve_id):
    # notas, vínculos de tecnologia e iscas somem junto (ON DELETE CASCADE)
    executar("DELETE FROM cves WHERE id = %s", (cve_id,))


# ------------------------------------------------------------------ referências (exploits públicos)

def referencias_da_cve(cve_id):
    return consultar("SELECT id, tipo, url, criado_em FROM referencias WHERE cve_id = %s ORDER BY tipo, criado_em",
                     (cve_id,))


def adicionar_referencia(cve_id, tipo, url):
    """Devolve 1 se gravou, 0 se o link já existia para essa CVE."""
    row = executar(
        "INSERT INTO referencias (cve_id, tipo, url) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING RETURNING id",
        (cve_id, tipo, url),
    )
    return 1 if row else 0


def excluir_referencia(ref_id):
    executar("DELETE FROM referencias WHERE id = %s", (ref_id,))


# ------------------------------------------------------------------ notas de mitigação

def notas_da_cve(cve_id):
    return consultar(
        """
        SELECT n.id, n.texto, n.criado_em, n.usuario_id, u.nome AS autor
          FROM notas n
          LEFT JOIN usuarios u ON u.id = n.usuario_id
         WHERE n.cve_id = %s
         ORDER BY n.criado_em, n.id
        """,
        (cve_id,),
    )


def criar_nota(cve_id, usuario_id, texto):
    executar("INSERT INTO notas (cve_id, usuario_id, texto) VALUES (%s, %s, %s)", (cve_id, usuario_id, texto))


def atualizar_nota(nota_id, texto):
    executar("UPDATE notas SET texto = %s WHERE id = %s", (texto, nota_id))


def excluir_nota(nota_id):
    executar("DELETE FROM notas WHERE id = %s", (nota_id,))


# ------------------------------------------------------------------ relatórios

def relatorio_por_severidade():
    return consultar(
        """
        SELECT severidade, COUNT(*) AS total, ROUND(AVG(cvss), 1) AS cvss_medio
          FROM cves
         GROUP BY severidade
         ORDER BY MAX(COALESCE(cvss, -1)) DESC
        """
    )


def relatorio_por_tecnologia():
    return consultar(
        """
        SELECT t.nome AS tecnologia, COUNT(ct.cve_id) AS total,
               COUNT(*) FILTER (WHERE c.severidade = 'critica') AS criticas
          FROM tecnologias t
          JOIN cve_tecnologias ct ON ct.tecnologia_id = t.id
          JOIN cves c             ON c.id = ct.cve_id
         GROUP BY t.nome
        HAVING COUNT(ct.cve_id) > 0
         ORDER BY total DESC, t.nome
        """
    )


def relatorio_mais_comentadas(limite=10):
    return consultar(
        """
        SELECT c.codigo, c.titulo, COUNT(n.id) AS notas
          FROM cves c
          JOIN notas n ON n.cve_id = c.id
         GROUP BY c.id
         ORDER BY notas DESC, c.codigo
         LIMIT %s
        """,
        (limite,),
    )


def relatorio_cves_sem_mitigacao():
    return consultar(
        """
        SELECT c.codigo, c.titulo, c.severidade
          FROM cves c
          LEFT JOIN notas n ON n.cve_id = c.id
         WHERE n.id IS NULL
         ORDER BY c.cvss DESC NULLS LAST
        """
    )


def relatorio_exploits_publicos():
    """CVEs com exploit público e sem nenhuma nota de mitigação: as mais urgentes."""
    return consultar(
        """
        SELECT c.codigo, c.titulo, c.severidade, COUNT(DISTINCT r.id) AS pocs,
               COUNT(DISTINCT n.id) AS notas
          FROM cves c
          JOIN referencias r ON r.cve_id = c.id AND r.tipo = 'poc'
          LEFT JOIN notas n  ON n.cve_id = c.id
         GROUP BY c.id
         ORDER BY (COUNT(DISTINCT n.id) = 0) DESC, pocs DESC
        """
    )


# ------------------------------------------------------------------ usuários (admin)

def listar_usuarios():
    return consultar("SELECT id, nome, email, papel, ativo, criado_em FROM usuarios ORDER BY nome")


def criar_usuario(nome, email, senha, papel):
    executar(
        "INSERT INTO usuarios (nome, email, senha_hash, papel) VALUES (%s, %s, crypt(%s, gen_salt('bf')), %s)",
        (nome, email.lower().strip(), senha, papel),
    )


def atualizar_usuario(usuario_id, nome, papel, ativo):
    executar("UPDATE usuarios SET nome = %s, papel = %s, ativo = %s WHERE id = %s",
             (nome, papel, ativo, usuario_id))


def excluir_usuario(usuario_id):
    executar("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
