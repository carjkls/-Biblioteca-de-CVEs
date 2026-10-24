"""Biblioteca de CVEs - interface Streamlit.

Rodar: streamlit run app/main.py
"""
import json
from datetime import date

import pandas as pd
import streamlit as st

import db
import honeypot
import telegram_import

st.set_page_config(page_title="Biblioteca de CVEs", page_icon="🛡️", layout="wide")

SEVERIDADES = ["critica", "alta", "media", "baixa", "desconhecida"]
ICONE_SEV = {"critica": "🟥", "alta": "🟧", "media": "🟨", "baixa": "🟩", "desconhecida": "⬜"}


# ================================================================== login

def tela_login():
    st.title("🛡️ Biblioteca de CVEs")
    st.caption("Consulta de vulnerabilidades para o time de desenvolvimento")
    with st.form("login"):
        email = st.text_input("E-mail")
        senha = st.text_input("Senha", type="password")
        if st.form_submit_button("Entrar", type="primary"):
            usuario = db.autenticar(email.lower().strip(), senha)
            if usuario:
                st.session_state.usuario = usuario
                st.rerun()
            else:
                st.error("E-mail ou senha inválidos.")


def usuario():
    return st.session_state.usuario


def eh_admin():
    return usuario()["papel"] == "admin"


# ================================================================== biblioteca (consulta + filtros)

def pagina_biblioteca():
    st.header("📚 Biblioteca")

    with st.sidebar:
        st.subheader("Filtros")
        texto = st.text_input("Buscar (código, título, descrição)")
        severidades = st.multiselect("Severidade", SEVERIDADES, placeholder="Todas")
        cvss_min, cvss_max = st.slider("CVSS", 0.0, 10.0, (0.0, 10.0), 0.1)
        anos = db.anos_disponiveis()
        ano = st.selectbox("Ano", [None] + anos, format_func=lambda a: "Todos" if a is None else str(a))
        tecs = db.listar_tecnologias()
        tec = st.selectbox("Tecnologia", [None] + tecs,
                           format_func=lambda t: "Todas" if t is None else t["nome"])
        origem = st.selectbox("Origem", [None, "manual", "telegram"],
                              format_func=lambda o: "Todas" if o is None else o)
        so_com_exploit = st.checkbox("Só com exploit público")

    if texto and st.session_state.get("ultima_busca") != texto:
        st.session_state.ultima_busca = texto
        honeypot.verificar_busca(usuario(), texto)

    cves = db.buscar_cves(texto, severidades, cvss_min, cvss_max, ano,
                          tec["id"] if tec else None, origem, so_com_exploit)
    st.caption(f"{len(cves)} CVE(s) encontrada(s). Clique numa linha para abrir.")
    if not cves:
        return

    iscas_cve, _ = honeypot.ids_isca() if eh_admin() else (set(), set())
    df = pd.DataFrame(cves)
    df["severidade"] = df["severidade"].map(lambda s: f"{ICONE_SEV[s]} {s}")
    if eh_admin():
        df["codigo"] = [f"🍯 {c}" if i in iscas_cve else c for i, c in zip(df["id"], df["codigo"])]

    evento = st.dataframe(
        df.drop(columns=["id"]),
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        key=f"tabela_{st.session_state.setdefault('tabela_versao', 0)}",
        column_config={
            "codigo": "Código", "titulo": "Título", "cvss": "CVSS", "severidade": "Severidade",
            "data_publicacao": st.column_config.DateColumn("Publicação", format="DD/MM/YYYY"),
            "origem": "Origem", "tecnologias": "Tecnologias", "qtd_notas": "Notas",
            "qtd_pocs": "Exploits",
        },
    )
    if evento.selection.rows:
        st.session_state.cve_aberta = int(df.iloc[evento.selection.rows[0]]["id"])
        st.session_state.tabela_versao += 1  # nova chave = tabela volta sem seleção
        st.session_state.ir_para = "Detalhe"
        st.rerun()


# ================================================================== detalhe / editar / excluir

def pagina_detalhe():
    cve_id = st.session_state.get("cve_aberta")
    cve = db.obter_cve(cve_id) if cve_id else None
    if not cve:
        st.info("Escolha uma CVE na Biblioteca.")
        return

    if st.session_state.get("cve_logada") != cve_id:
        st.session_state.cve_logada = cve_id
        st.session_state.notas_abertas = set()
        honeypot.registrar_acesso_cve(usuario(), cve_id)

    if st.button("← Voltar para a biblioteca"):
        st.session_state.ir_para = "Biblioteca"
        st.rerun()

    st.header(f"{ICONE_SEV[cve['severidade']]} {cve['codigo']}")
    st.subheader(cve["titulo"])
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("CVSS", cve["cvss"] if cve["cvss"] is not None else "—")
    c2.metric("Severidade", cve["severidade"])
    c3.metric("Publicação", cve["data_publicacao"].strftime("%d/%m/%Y") if cve["data_publicacao"] else "—")
    c4.metric("Origem", cve["origem"])
    tecs = db.tecnologias_da_cve(cve_id)
    st.write("**Tecnologias:** " + (", ".join(t["nome"] for t in tecs) or "nenhuma"))
    if cve["descricao"]:
        st.write(cve["descricao"])
    if cve["link_referencia"]:
        st.write(f"[Referência]({cve['link_referencia']})")
    st.caption(f"Cadastrada por {cve['criado_por_nome'] or '—'} em {cve['criado_em']:%d/%m/%Y %H:%M}")

    refs = db.referencias_da_cve(cve_id)
    pocs = [r for r in refs if r["tipo"] == "poc"]
    if pocs:
        st.error(f"⚠️ Existe(m) {len(pocs)} exploit(s) público(s) para esta falha. Priorize a correção.")
    if refs or eh_admin():
        with st.expander(f"🔗 Referências ({len(refs)})", expanded=bool(pocs)):
            for r in refs:
                a, b = st.columns([6, 1])
                a.write(f"`{r['tipo']}` {r['url']}")
                if eh_admin() and b.button("Remover", key=f"ref_{r['id']}"):
                    db.excluir_referencia(r["id"])
                    st.rerun()
            if eh_admin():
                with st.form("nova_ref", clear_on_submit=True):
                    tipo = st.selectbox("Tipo", ["poc", "advisory", "outro"])
                    url = st.text_input("URL")
                    if st.form_submit_button("Adicionar") and url.strip():
                        db.adicionar_referencia(cve_id, tipo, url.strip())
                        st.rerun()

    if eh_admin():
        with st.expander("✏️ Editar CVE"):
            formulario_cve(cve, [t["id"] for t in tecs])
        with st.expander("🗑️ Excluir CVE"):
            st.warning("Isso apaga também as notas e os vínculos com tecnologias.")
            if st.button("Confirmar exclusão", type="primary"):
                db.excluir_cve(cve_id)
                st.session_state.cve_aberta = None
                st.session_state.ir_para = "Biblioteca"
                st.rerun()

    secao_notas(cve_id)


def secao_notas(cve_id):
    st.divider()
    st.subheader("🩹 Notas de mitigação do time")
    _, iscas_nota = honeypot.ids_isca()
    abertas = st.session_state.setdefault("notas_abertas", set())

    for nota in db.notas_da_cve(cve_id):
        with st.container(border=True):
            selo = " 🍯 isca" if eh_admin() and nota["id"] in iscas_nota else ""
            st.caption(f"{nota['autor'] or '—'} · {nota['criado_em']:%d/%m/%Y %H:%M}{selo}")
            if eh_admin() or nota["id"] in abertas:
                st.write(nota["texto"])
            elif st.button("Ver mitigação", key=f"ver_{nota['id']}"):
                abertas.add(nota["id"])
                honeypot.registrar_acesso_nota(usuario(), cve_id, nota["id"])
                st.rerun()

            if eh_admin() or nota["usuario_id"] == usuario()["id"]:
                with st.popover("Editar / excluir"):
                    novo = st.text_area("Texto", nota["texto"], key=f"txt_{nota['id']}")
                    a, b = st.columns(2)
                    if a.button("Salvar", key=f"salvar_{nota['id']}"):
                        db.atualizar_nota(nota["id"], novo)
                        st.rerun()
                    if b.button("Excluir", key=f"excluir_{nota['id']}"):
                        db.excluir_nota(nota["id"])
                        st.rerun()

    with st.form("nova_nota", clear_on_submit=True):
        texto = st.text_area("Como você mitigou essa falha?")
        if st.form_submit_button("Adicionar nota") and texto.strip():
            db.criar_nota(cve_id, usuario()["id"], texto.strip())
            st.rerun()


# ================================================================== cadastrar / editar

def formulario_cve(cve=None, tec_ids_atuais=()):
    tecs = db.listar_tecnologias()
    chave = f"form_cve_{cve['id'] if cve else 'nova'}"
    with st.form(chave):
        codigo = st.text_input("Código (CVE-AAAA-NNNN)", cve["codigo"] if cve else "")
        titulo = st.text_input("Título", cve["titulo"] if cve else "")
        descricao = st.text_area("Descrição", cve["descricao"] if cve else "")
        sem_cvss = st.checkbox("CVSS desconhecido", value=bool(cve and cve["cvss"] is None))
        cvss = st.number_input("CVSS", 0.0, 10.0, float(cve["cvss"]) if cve and cve["cvss"] is not None else 5.0, 0.1)
        data_pub = st.date_input("Data de publicação", cve["data_publicacao"] if cve and cve["data_publicacao"] else date.today(),
                                 format="DD/MM/YYYY")
        link = st.text_input("Link de referência", cve["link_referencia"] if cve and cve["link_referencia"] else "")
        selecionadas = st.multiselect("Tecnologias", tecs, default=[t for t in tecs if t["id"] in tec_ids_atuais],
                                      format_func=lambda t: t["nome"])
        nova_tec = st.text_input("Nova tecnologia (opcional)")
        if not st.form_submit_button("Salvar", type="primary"):
            return

    if not codigo.strip() or not titulo.strip():
        st.error("Código e título são obrigatórios.")
        return
    tec_ids = [t["id"] for t in selecionadas]
    if nova_tec.strip():
        tec_ids.append(db.criar_tecnologia(nova_tec))
    valor_cvss = None if sem_cvss else cvss
    try:
        if cve:
            db.atualizar_cve(cve["id"], codigo, titulo, descricao, valor_cvss, data_pub, link or None, tec_ids)
            st.success("CVE atualizada.")
        else:
            novo_id = db.criar_cve(codigo, titulo, descricao, valor_cvss, data_pub, link or None,
                                   tec_ids, usuario()["id"])
            if novo_id is None:
                st.error("Já existe uma CVE com esse código.")
                return
            st.session_state.cve_aberta = novo_id
            st.session_state.ir_para = "Detalhe"
        st.rerun()
    except db.psycopg.errors.CheckViolation:
        st.error("Código inválido. Use o formato CVE-2024-12345.")
    except db.psycopg.errors.UniqueViolation:
        st.error("Já existe uma CVE com esse código.")


def pagina_nova_cve():
    st.header("➕ Cadastrar CVE")
    formulario_cve()


# ================================================================== relatórios

def pagina_relatorios():
    st.header("📊 Relatórios")
    a, b = st.columns(2)
    with a:
        st.subheader("Por severidade")
        st.dataframe(db.relatorio_por_severidade(), hide_index=True, width="stretch")
        st.subheader("Mais comentadas")
        st.dataframe(db.relatorio_mais_comentadas(), hide_index=True, width="stretch")
    with b:
        st.subheader("Por tecnologia")
        por_tec = db.relatorio_por_tecnologia()
        if por_tec:
            st.bar_chart(pd.DataFrame(por_tec).set_index("tecnologia")["total"])
        st.subheader("Sem nenhuma nota de mitigação")
        st.dataframe(db.relatorio_cves_sem_mitigacao(), hide_index=True, width="stretch")
    st.subheader("⚠️ Com exploit público (sem nota de mitigação primeiro)")
    st.dataframe(db.relatorio_exploits_publicos(), hide_index=True, width="stretch")


# ================================================================== importar do Telegram

def pagina_importar():
    st.header("📥 Importar do Telegram")
    aba_texto, aba_json = st.tabs(["Colar mensagens", "Arquivo JSON exportado"])
    mensagens = None

    with aba_texto:
        st.markdown("Selecione as mensagens no Telegram, copie (Ctrl+C) e cole aqui.")
        colado = st.text_area("Mensagens", height=250,
                              placeholder='[24/10/2026 06:20] CVE Monitor: {\n"Source": "CVE FEED", ...')
        if colado.strip():
            mensagens = list(telegram_import.mensagens_do_texto(colado))

    with aba_json:
        st.markdown(
            "No **Telegram Desktop**, abra o chat → ⋮ → **Exportar histórico do chat** → "
            "desmarque mídias → formato **JSON**. Envie aqui o `result.json`."
        )
        arquivo = st.file_uploader("result.json", type="json")
        if arquivo:
            try:
                mensagens = list(telegram_import.mensagens_do_json(json.load(arquivo)))
            except (json.JSONDecodeError, AttributeError):
                st.error("Arquivo não é uma exportação JSON válida do Telegram.")

    if not mensagens:
        return
    cves = telegram_import.extrair_cves(mensagens)
    st.write(f"{len(mensagens)} mensagem(ns), {len(cves)} CVE(s) diferente(s) encontrada(s).")
    if not cves:
        return
    previa = pd.DataFrame(cves)
    previa["pocs"] = previa["pocs"].map(len)
    st.dataframe(previa[["codigo", "titulo", "cvss", "data_publicacao", "pocs"]],
                 hide_index=True, width="stretch",
                 column_config={"codigo": "Código", "titulo": "Título", "cvss": "CVSS",
                                "data_publicacao": "Publicação", "pocs": "Exploits"})
    if st.button("Importar", type="primary"):
        novas, existentes, pocs = telegram_import.importar(cves, usuario()["id"])
        st.success(f"{novas} CVE(s) nova(s), {existentes} já existiam (completei o que faltava), "
                   f"{pocs} link(s) de exploit adicionados.")


# ================================================================== honeypot (admin)

MOTIVOS = {"isca_cve": "Abriu CVE isca", "isca_nota": "Abriu nota isca",
           "busca_suspeita": "Busca suspeita", "volume": "Muitas notas em pouco tempo"}


def pagina_honeypot():
    st.header("🍯 Honeypot")
    st.caption("Iscas para detectar quem procura como o time mitigou falhas para tentar contorná-las.")

    aba_alertas, aba_iscas, aba_nova = st.tabs(["Alertas", "Iscas", "Nova isca"])

    with aba_alertas:
        ranking = honeypot.ranking_suspeitos()
        if ranking:
            st.subheader("Usuários com mais alertas")
            st.dataframe(ranking, hide_index=True, width="stretch")
        motivo = st.selectbox("Motivo", [None] + list(MOTIVOS),
                              format_func=lambda m: "Todos" if m is None else MOTIVOS[m])
        alertas = honeypot.listar_alertas(motivo)
        if alertas:
            df = pd.DataFrame(alertas)
            df["motivo"] = df["motivo"].map(MOTIVOS)
            st.dataframe(df, hide_index=True, width="stretch")
        else:
            st.info("Nenhum alerta até agora.")

    with aba_iscas:
        for h in honeypot.listar_honeypots():
            with st.container(border=True):
                st.write(f"**#{h['id']} · {h['tipo']}** · {h['cve']} · {h['descricao'] or ''}")
                if h["nota"]:
                    st.caption(h["nota"] + "…")
                a, b, c = st.columns([2, 1, 1])
                a.write(f"{h['alertas']} alerta(s) · {'ativa' if h['ativo'] else 'desativada'}")
                if b.button("Desativar" if h["ativo"] else "Ativar", key=f"alt_{h['id']}"):
                    honeypot.alternar_honeypot(h["id"], not h["ativo"])
                    st.rerun()
                if c.button("Excluir", key=f"exc_{h['id']}"):
                    honeypot.excluir_honeypot(h["id"])
                    st.rerun()

    with aba_nova:
        cves = db.buscar_cves()
        tipo = st.radio("Tipo de isca", ["Marcar uma CVE inteira como isca", "Plantar nota de mitigação falsa"])
        alvo = st.selectbox("CVE", cves, format_func=lambda c: f"{c['codigo']} · {c['titulo']}")
        descricao = st.text_input("Descrição interna (só o admin vê)")
        texto = ""
        if tipo.startswith("Plantar"):
            texto = st.text_area("Texto da nota falsa",
                                 placeholder="Ex.: rota /api/v1/old ainda sem a correção, usar token interno ...")
        if st.button("Criar isca", type="primary") and alvo:
            if tipo.startswith("Marcar"):
                honeypot.criar_honeypot_cve(alvo["id"], descricao)
            elif texto.strip():
                honeypot.criar_honeypot_nota(alvo["id"], usuario()["id"], texto.strip(), descricao)
            else:
                st.error("Escreva o texto da nota falsa.")
                return
            st.success("Isca criada.")


# ================================================================== usuários (admin)

def pagina_usuarios():
    st.header("👥 Usuários")
    for u in db.listar_usuarios():
        with st.expander(f"{u['nome']} · {u['email']} · {u['papel']}{'' if u['ativo'] else ' · inativo'}"):
            with st.form(f"usr_{u['id']}"):
                nome = st.text_input("Nome", u["nome"])
                papel = st.selectbox("Papel", ["dev", "admin"], index=["dev", "admin"].index(u["papel"]))
                ativo = st.checkbox("Ativo", u["ativo"])
                a, b = st.columns(2)
                if a.form_submit_button("Salvar"):
                    db.atualizar_usuario(u["id"], nome, papel, ativo)
                    st.rerun()
                if b.form_submit_button("Excluir") and u["id"] != usuario()["id"]:
                    db.excluir_usuario(u["id"])
                    st.rerun()

    st.subheader("Novo usuário")
    with st.form("novo_usuario", clear_on_submit=True):
        nome = st.text_input("Nome")
        email = st.text_input("E-mail")
        senha = st.text_input("Senha", type="password")
        papel = st.selectbox("Papel", ["dev", "admin"])
        if st.form_submit_button("Cadastrar", type="primary"):
            if not (nome and email and senha):
                st.error("Preencha todos os campos.")
            else:
                try:
                    db.criar_usuario(nome, email, senha, papel)
                    st.rerun()
                except db.psycopg.errors.UniqueViolation:
                    st.error("E-mail já cadastrado.")


# ================================================================== navegação

def main():
    if "usuario" not in st.session_state:
        tela_login()
        return

    paginas = {"Biblioteca": pagina_biblioteca, "Detalhe": pagina_detalhe, "Relatórios": pagina_relatorios}
    if eh_admin():
        paginas |= {"Cadastrar CVE": pagina_nova_cve, "Importar Telegram": pagina_importar,
                    "Honeypot": pagina_honeypot, "Usuários": pagina_usuarios}

    if "ir_para" in st.session_state:
        st.session_state.pagina = st.session_state.pop("ir_para")

    with st.sidebar:
        st.write(f"👤 **{usuario()['nome']}** ({usuario()['papel']})")
        if st.button("Sair"):
            st.session_state.clear()
            st.rerun()
        st.radio("Menu", list(paginas), key="pagina")
        st.divider()

    paginas[st.session_state.pagina]()


main()
