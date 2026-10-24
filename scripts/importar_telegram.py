"""Importa CVEs do Telegram pelo terminal.

Uso: python scripts/importar_telegram.py ARQUIVO [email_do_admin]

ARQUIVO pode ser o result.json exportado pelo Telegram Desktop ou um .txt
com mensagens copiadas do chat.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

import db  # noqa: E402
import telegram_import  # noqa: E402

if len(sys.argv) < 2:
    sys.exit(__doc__)

email = sys.argv[2] if len(sys.argv) > 2 else "admin@cves.local"
admin = db.consultar_um("SELECT id FROM usuarios WHERE email = %s", (email,))
if not admin:
    sys.exit(f"Usuário {email} não encontrado.")

conteudo = Path(sys.argv[1]).read_text(encoding="utf-8")
if sys.argv[1].endswith(".json"):
    mensagens = telegram_import.mensagens_do_json(json.loads(conteudo))
else:
    mensagens = telegram_import.mensagens_do_texto(conteudo)

cves = telegram_import.extrair_cves(mensagens)
novas, existentes, pocs = telegram_import.importar(cves, admin["id"])
print(f"{len(cves)} CVE(s) no arquivo: {novas} nova(s), {existentes} já existiam, {pocs} link(s) de exploit.")
