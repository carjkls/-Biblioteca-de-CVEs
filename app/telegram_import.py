"""Importa CVEs do Telegram.

Aceita dois formatos:
  - a exportação JSON do Telegram Desktop (result.json);
  - texto copiado direto do chat ("[24/10/2026 06:20] CVE Monitor: {...}").

Entende o padrão do canal CVE Monitor (t.me/cvedetector): campos "Title", "Source",
"Type", "Description :", "Severity: 7.1 | HIGH". Mensagens do tipo "Exploit POC"
viram referências de exploit público para a CVE. Mensagens fora desse padrão
caem na regra genérica: qualquer CVE-AAAA-NNNN citada no texto.
"""
import re
from datetime import date, datetime

import db

RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
RE_LINK = re.compile(r"https?://[^\s\"'<>]+")
RE_CABECALHO = re.compile(r"^\[(\d{2})/(\d{2})/(\d{4}) \d{2}:\d{2}\] [^:\n]+:", re.MULTILINE)

RE_TITULO = re.compile(r'"Title"\s*:\s*"(.+?)"\s*,?\s*$', re.MULTILINE)
RE_FONTE = re.compile(r'"Source"\s*:\s*"(.+?)"')
RE_TIPO = re.compile(r'"Type"\s*:\s*"(.+?)"')
RE_DESCRICAO = re.compile(
    r"Description\s*:\s*(.+?)(?=\n\s*Severity\s*:|\n\s*Visit the link|\n\s*##|\Z)", re.DOTALL)
RE_PUBLICADO = re.compile(r"Published\s*:\s*([A-Za-z]{3})[a-z]*\.?\s+(\d{1,2}),\s*(\d{4})")
RE_DATA_TITULO = re.compile(r"\((\d{4}-\d{2}-\d{2})\)")

# ordem importa: "CVSS 3.1" é a versão do CVSS, não a nota
RE_NOTAS = [
    re.compile(r"Severity\s*:\s*(\d{1,2}(?:[.,]\d)?)", re.IGNORECASE),
    re.compile(r"\bscores?\s+(\d{1,2}(?:[.,]\d)?)", re.IGNORECASE),
    re.compile(r"CVSS(?:\s*v?\d(?:\.\d)?)?\s*(?:score)?\s*[:=]\s*(\d{1,2}(?:[.,]\d)?)", re.IGNORECASE),
]
MESES = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}


# ------------------------------------------------------------------ entrada: JSON ou texto colado

def texto_da_mensagem(msg):
    """O campo 'text' vem como string ou como lista de pedaços (string ou dict com 'text' e às vezes 'href')."""
    texto = msg.get("text", "")
    if isinstance(texto, str):
        return texto, []
    partes, links = [], []
    for parte in texto:
        if isinstance(parte, str):
            partes.append(parte)
        else:
            partes.append(parte.get("text", ""))
            if parte.get("href"):
                links.append(parte["href"])
    return "".join(partes), links


def mensagens_do_json(export):
    for msg in export.get("messages", []):
        if msg.get("type") != "message":
            continue
        texto, links = texto_da_mensagem(msg)
        data = msg.get("date", "")[:10]
        yield texto, (date.fromisoformat(data) if data else None), links, msg.get("id")


def mensagens_do_texto(colado):
    """Quebra o texto copiado do Telegram em mensagens pelo cabeçalho [dd/mm/aaaa hh:mm] Autor:"""
    cabecalhos = list(RE_CABECALHO.finditer(colado))
    if not cabecalhos:
        yield colado, None, [], None
        return
    for i, cab in enumerate(cabecalhos):
        fim = cabecalhos[i + 1].start() if i + 1 < len(cabecalhos) else len(colado)
        dia, mes, ano = cab.groups()
        yield colado[cab.end():fim], date(int(ano), int(mes), int(dia)), [], None


# ------------------------------------------------------------------ interpretação de uma mensagem

def _nota_cvss(texto):
    for regex in RE_NOTAS:
        achou = regex.search(texto)
        if achou:
            valor = float(achou.group(1).replace(",", "."))
            if 0 <= valor <= 10:
                return valor
    return None


def _data_publicacao(texto, titulo, data_msg):
    achou = RE_PUBLICADO.search(texto)
    if achou and achou.group(1).lower() in MESES:
        return date(int(achou.group(3)), MESES[achou.group(1).lower()], int(achou.group(2)))
    achou = RE_DATA_TITULO.search(titulo or "")
    if achou:
        return date.fromisoformat(achou.group(1))
    return data_msg


def _limpar(texto):
    return re.sub(r"\s+", " ", texto).strip().strip('",').strip()


def _resumo(texto, limite=150):
    frase = re.split(r"(?<=[.!?])\s", texto, maxsplit=1)[0]
    return frase if len(frase) <= limite else frase[:limite - 1].rsplit(" ", 1)[0] + "…"


def analisar_mensagem(texto, data_msg=None, links=(), msg_id=None, tecnologias=()):
    """Devolve uma lista de dicts, um por CVE citada na mensagem."""
    titulo_bruto = RE_TITULO.search(texto)
    titulo_bruto = titulo_bruto.group(1) if titulo_bruto else None
    tipo = RE_TIPO.search(texto)
    eh_poc = bool(tipo and "poc" in tipo.group(1).lower())
    fonte = RE_FONTE.search(texto)
    fonte = fonte.group(1) if fonte and fonte.group(1).startswith("http") else None

    # no padrão CVE Monitor a CVE da mensagem é a do título; o resto do texto pode citar outras de passagem
    codigos = RE_CVE.findall(titulo_bruto) if titulo_bruto else []
    codigos = codigos or RE_CVE.findall(texto)
    codigos = list(dict.fromkeys(c.upper() for c in codigos))
    if not codigos:
        return []

    if eh_poc:
        conteudo = re.search(r'"Content"\s*:\s*"(.*?)\[GitHub\]', texto, re.DOTALL)
        descricao = _limpar(conteudo.group(1)) if conteudo else _limpar(texto)
        titulo = _resumo(descricao)
    else:
        achou = RE_DESCRICAO.search(texto)
        descricao = _limpar(achou.group(1)) if achou else _limpar(texto)
        if titulo_bruto:
            titulo = re.sub(r"^CVE-\d{4}-\d+\s*[-–:]\s*", "", titulo_bruto, flags=re.IGNORECASE).strip()
        else:
            titulo = next((l.strip() for l in texto.splitlines() if l.strip()), codigos[0])

    texto_baixo = texto.lower()
    tec_ids = [t["id"] for t in tecnologias
               if re.search(rf"(?<!\w){re.escape(t['nome'].lower())}(?!\w)", texto_baixo)]
    links = list(links) + RE_LINK.findall(texto)

    resultado = []
    for codigo in codigos:
        link = next((l for l in links if codigo.lower() in l.lower()), None)
        resultado.append({
            "codigo": codigo,
            "titulo": titulo[:200],
            "descricao": None if eh_poc and not descricao else descricao,
            "cvss": _nota_cvss(texto),
            "data_publicacao": _data_publicacao(texto, titulo_bruto, data_msg),
            "link": link or f"https://nvd.nist.gov/vuln/detail/{codigo}",
            "tecnologia_ids": tec_ids,
            "telegram_msg_id": msg_id,
            "poc": fonte if eh_poc else None,
        })
    return resultado


def extrair_cves(mensagens):
    """Junta as mensagens por código. A primeira menção dá os dados; as seguintes completam o que faltar
    e acumulam os links de PoC."""
    tecnologias = db.listar_tecnologias()
    por_codigo = {}
    for texto, data_msg, links, msg_id in mensagens:
        for cve in analisar_mensagem(texto, data_msg, links, msg_id, tecnologias):
            atual = por_codigo.setdefault(cve["codigo"], {**cve, "pocs": []})
            for campo in ("cvss", "descricao", "data_publicacao"):
                if atual[campo] is None:
                    atual[campo] = cve[campo]
            atual["tecnologia_ids"] = sorted(set(atual["tecnologia_ids"]) | set(cve["tecnologia_ids"]))
            if cve["poc"] and cve["poc"] not in atual["pocs"]:
                atual["pocs"].append(cve["poc"])
    return list(por_codigo.values())


def importar(cves, usuario_id):
    """Grava no banco. Devolve (novas, atualizadas, pocs)."""
    novas = atualizadas = pocs = 0
    for cve in cves:
        cve_id, inserida = db.importar_cve(cve, usuario_id)
        novas += inserida
        atualizadas += not inserida
        for url in cve["pocs"]:
            pocs += db.adicionar_referencia(cve_id, "poc", url)
    return novas, atualizadas, pocs
