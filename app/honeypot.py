"""Honeypot: iscas, auditoria de acessos e alertas de segurança.

Só usuários com papel 'dev' geram alertas: o admin é quem planta as iscas.
"""
from db import consultar, consultar_um, executar

# Mais de N notas de mitigação abertas em X minutos vira alerta de volume
LIMITE_NOTAS = 8
JANELA_MINUTOS = 10


def _isca_ativa(coluna, valor):
    return consultar_um(
        f"SELECT id FROM honeypots WHERE {coluna} = %s AND ativo",
        (valor,),
    )


def _alertar(usuario, motivo, honeypot_id=None, termo=None):
    if usuario["papel"] == "admin":
        return
    executar(
        "INSERT INTO alertas_seguranca (usuario_id, honeypot_id, motivo, termo_busca) VALUES (%s, %s, %s, %s)",
        (usuario["id"], honeypot_id, motivo, termo),
    )


def registrar_acesso_cve(usuario, cve_id):
    executar("INSERT INTO log_acessos (usuario_id, cve_id) VALUES (%s, %s)", (usuario["id"], cve_id))
    isca = _isca_ativa("cve_id", cve_id)
    if isca:
        _alertar(usuario, "isca_cve", isca["id"])


def registrar_acesso_nota(usuario, cve_id, nota_id):
    executar("INSERT INTO log_acessos (usuario_id, cve_id, nota_id) VALUES (%s, %s, %s)",
             (usuario["id"], cve_id, nota_id))
    isca = _isca_ativa("nota_id", nota_id)
    if isca:
        _alertar(usuario, "isca_nota", isca["id"])

    abertas = consultar_um(
        """
        SELECT COUNT(*) AS total
          FROM log_acessos
         WHERE usuario_id = %s
           AND nota_id IS NOT NULL
           AND criado_em > NOW() - make_interval(mins => %s)
        """,
        (usuario["id"], JANELA_MINUTOS),
    )["total"]
    if abertas == LIMITE_NOTAS + 1:  # alerta uma vez ao cruzar o limite, não a cada clique
        _alertar(usuario, "volume", termo=f"{abertas} notas em {JANELA_MINUTOS} min")


def verificar_busca(usuario, texto):
    if not texto:
        return
    termo = consultar_um(
        "SELECT termo FROM termos_suspeitos WHERE %s ILIKE '%%' || termo || '%%' LIMIT 1",
        (texto,),
    )
    if termo:
        _alertar(usuario, "busca_suspeita", termo=texto)


# ------------------------------------------------------------------ painel do admin

def ids_isca():
    """CVEs e notas marcadas como isca (para o admin enxergar o selo)."""
    rows = consultar("SELECT cve_id, nota_id FROM honeypots WHERE ativo")
    return ({r["cve_id"] for r in rows if r["cve_id"]},
            {r["nota_id"] for r in rows if r["nota_id"]})


def listar_honeypots():
    return consultar(
        """
        SELECT h.id, h.tipo, h.descricao, h.ativo, h.criado_em,
               COALESCE(c.codigo, cn.codigo) AS cve,
               LEFT(n.texto, 80)             AS nota,
               COUNT(a.id)                   AS alertas
          FROM honeypots h
          LEFT JOIN cves c   ON c.id = h.cve_id
          LEFT JOIN notas n  ON n.id = h.nota_id
          LEFT JOIN cves cn  ON cn.id = n.cve_id
          LEFT JOIN alertas_seguranca a ON a.honeypot_id = h.id
         GROUP BY h.id, c.codigo, cn.codigo, n.texto
         ORDER BY h.id
        """
    )


def criar_honeypot_cve(cve_id, descricao):
    executar("INSERT INTO honeypots (tipo, cve_id, descricao) VALUES ('cve', %s, %s)", (cve_id, descricao))


def criar_honeypot_nota(cve_id, usuario_id, texto, descricao):
    nota = executar(
        "INSERT INTO notas (cve_id, usuario_id, texto) VALUES (%s, %s, %s) RETURNING id",
        (cve_id, usuario_id, texto),
    )
    executar("INSERT INTO honeypots (tipo, nota_id, descricao) VALUES ('nota', %s, %s)", (nota["id"], descricao))


def alternar_honeypot(honeypot_id, ativo):
    executar("UPDATE honeypots SET ativo = %s WHERE id = %s", (ativo, honeypot_id))


def excluir_honeypot(honeypot_id):
    executar("DELETE FROM honeypots WHERE id = %s", (honeypot_id,))


def listar_alertas(motivo=None, usuario_id=None):
    filtros, params = ["TRUE"], []
    if motivo:
        filtros.append("a.motivo = %s")
        params.append(motivo)
    if usuario_id:
        filtros.append("a.usuario_id = %s")
        params.append(usuario_id)
    return consultar(
        f"""
        SELECT a.criado_em AS quando, u.nome AS usuario, u.email, a.motivo,
               h.descricao AS isca, a.termo_busca
          FROM alertas_seguranca a
          LEFT JOIN usuarios u  ON u.id = a.usuario_id
          LEFT JOIN honeypots h ON h.id = a.honeypot_id
         WHERE {' AND '.join(filtros)}
         ORDER BY a.criado_em DESC
        """,
        params,
    )


def ranking_suspeitos():
    return consultar(
        """
        SELECT u.nome, u.email, COUNT(*) AS alertas, MAX(a.criado_em) AS ultimo
          FROM alertas_seguranca a
          JOIN usuarios u ON u.id = a.usuario_id
         GROUP BY u.id
         ORDER BY alertas DESC
        """
    )
