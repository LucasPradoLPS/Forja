#!/usr/bin/env python3
"""
Checador passivo de SPF / DMARC / DKIM.

Só faz consultas DNS públicas (TXT/MX/A) contra os resolvers — nenhum pacote
é enviado ao servidor de e-mail ou web do alvo. Aponta configurações que
permitem (ou facilitam) spoofing do domínio.

Uso:
    python email_dns_check.py exemplo.com
    python email_dns_check.py a.com b.com --json
    python email_dns_check.py -f dominios.txt --selectors meuselector,k2
    python email_dns_check.py exemplo.com --resolver 1.1.1.1

Use apenas em domínios seus ou com autorização para auditoria.
"""
import argparse
import base64
import json
import re
import sys
from dataclasses import dataclass, field, asdict

try:
    import dns.resolver
    import dns.exception
except ImportError:
    sys.exit("Falta a dependência: pip install dnspython")

# Seletores DKIM comuns (não há como listar seletores via DNS; é tentativa).
COMMON_SELECTORS = [
    "default", "dkim", "mail", "email", "smtp", "k1", "k2", "k3",
    "selector1", "selector2",            # Microsoft 365
    "google", "20230601", "20221208",    # Google Workspace / datas comuns
    "s1", "s2",                          # SendGrid
    "mandrill", "mte1", "mte2",          # Mandrill / Mailchimp
    "pm", "smtpapi", "cm", "zoho", "zmail", "mxvault", "protonmail",
    "protonmail2", "protonmail3", "scph1220", "everlytickey1", "turbo-smtp",
]

SEV_ORDER = {"CRÍTICO": 0, "ALTO": 1, "MÉDIO": 2, "BAIXO": 3, "INFO": 4, "OK": 5}


@dataclass
class Finding:
    severity: str
    area: str
    message: str


@dataclass
class Report:
    domain: str
    mx: list = field(default_factory=list)
    spf: str | None = None
    spf_lookups: int = 0
    dmarc: str | None = None
    dmarc_tags: dict = field(default_factory=dict)
    dkim: dict = field(default_factory=dict)  # selector -> registro
    findings: list = field(default_factory=list)
    spoofable: str = "?"

    def add(self, sev, area, msg):
        self.findings.append(Finding(sev, area, msg))


class DNS:
    def __init__(self, nameserver=None, timeout=5.0):
        self.r = dns.resolver.Resolver(configure=nameserver is None)
        if nameserver:
            self.r.nameservers = [nameserver]
        self.r.lifetime = timeout
        self.r.timeout = timeout

    def txt(self, name):
        """Retorna lista de TXT (strings concatenadas) ou [] se não existe."""
        try:
            ans = self.r.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        return ["".join(p.decode("utf-8", "replace") for p in rd.strings)
                for rd in ans]

    def mx(self, name):
        try:
            return sorted((rd.preference, str(rd.exchange).rstrip(".") or ".")
                          for rd in self.r.resolve(name, "MX"))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []

    def exists(self, name):
        for rtype in ("A", "AAAA"):
            try:
                self.r.resolve(name, rtype)
                return True
            except Exception:
                pass
        return False


# ---------------------------------------------------------------- SPF ----

def count_spf_lookups(d: DNS, record: str, seen=None, depth=0):
    """Conta mecanismos que geram consulta DNS (limite RFC 7208 = 10)."""
    seen = seen if seen is not None else set()
    total = 0
    notes = []
    if depth > 10:
        return total, notes
    for term in record.split()[1:]:
        t = term.lstrip("+-~?")
        low = t.lower()
        if low.startswith("include:"):
            total += 1
            target = t.split(":", 1)[1]
            if target in seen:
                continue
            seen.add(target)
            sub = [x for x in d.txt(target) if x.lower().startswith("v=spf1")]
            if not sub:
                notes.append(f"include:{target} não retorna SPF válido (permerror)")
                continue
            n, nn = count_spf_lookups(d, sub[0], seen, depth + 1)
            total += n
            notes += nn
        elif low.startswith("redirect="):
            total += 1
            target = t.split("=", 1)[1]
            if target not in seen:
                seen.add(target)
                sub = [x for x in d.txt(target) if x.lower().startswith("v=spf1")]
                if sub:
                    n, nn = count_spf_lookups(d, sub[0], seen, depth + 1)
                    total += n
                    notes += nn
        elif (low in ("a", "mx", "ptr") or low.startswith(("a:", "a/", "mx:", "mx/",
                                                           "ptr:", "exists:"))):
            total += 1
    return total, notes


def check_spf(d: DNS, rep: Report):
    records = [t for t in d.txt(rep.domain) if t.lower().startswith("v=spf1")]
    if not records:
        rep.add("CRÍTICO", "SPF", "Nenhum registro SPF — qualquer servidor pode "
                "enviar e-mail em nome do domínio sem falhar no SPF.")
        return
    if len(records) > 1:
        rep.add("ALTO", "SPF", f"{len(records)} registros SPF publicados — "
                "isso gera permerror e o SPF é ignorado (RFC 7208 §4.5).")
    rec = records[0]
    rep.spf = rec
    terms = rec.split()

    all_term = next((t for t in terms if t.lstrip("+-~?").lower() == "all"), None)
    redirect = any(t.lower().startswith("redirect=") for t in terms)
    if all_term is None and not redirect:
        rep.add("ALTO", "SPF", "Sem mecanismo 'all' final — remetentes não listados "
                "recebem resultado neutro (efetivamente permissivo).")
    elif all_term is not None:
        q = all_term[0] if all_term[0] in "+-~?" else "+"
        if q == "+":
            rep.add("CRÍTICO", "SPF", f"'{all_term}' autoriza QUALQUER servidor a enviar.")
        elif q == "?":
            rep.add("ALTO", "SPF", f"'{all_term}' (neutral) não protege contra spoofing.")
        elif q == "~":
            rep.add("MÉDIO", "SPF", "'~all' (softfail) — spoofing é marcado, mas "
                    "geralmente entregue. Prefira '-all' junto com DMARC enforce.")
        else:
            rep.add("OK", "SPF", "'-all' (hardfail) configurado.")

    if any(t.lower().lstrip("+-~?").startswith("ptr") for t in terms):
        rep.add("MÉDIO", "SPF", "Uso do mecanismo 'ptr' (desencorajado pela RFC 7208).")

    # Faixas IP muito largas
    for t in terms:
        m = re.match(r"[+]?ip4:([\d.]+)/(\d+)$", t, re.I)
        if m and int(m.group(2)) <= 16:
            rep.add("MÉDIO", "SPF", f"Faixa IP muito ampla: {t}")

    n, notes = count_spf_lookups(d, rec)
    rep.spf_lookups = n
    if n > 10:
        rep.add("ALTO", "SPF", f"{n} consultas DNS (limite 10) — SPF dá permerror "
                "e falha para todos.")
    elif n >= 8:
        rep.add("BAIXO", "SPF", f"{n}/10 consultas DNS — perto do limite.")
    for note in notes:
        rep.add("MÉDIO", "SPF", note)

    if len(rec) > 450:
        rep.add("BAIXO", "SPF", f"Registro longo ({len(rec)} chars) — atenção ao "
                "limite de 512 bytes de resposta UDP.")


# -------------------------------------------------------------- DMARC ----

def parse_tags(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(d: DNS, rep: Report):
    records = [t for t in d.txt(f"_dmarc.{rep.domain}")
               if t.lower().replace(" ", "").startswith("v=dmarc1")]
    if not records:
        # Política herdada do domínio organizacional (subdomínios)
        parts = rep.domain.split(".")
        if len(parts) > 2:
            org = ".".join(parts[-2:])
            inherited = [t for t in d.txt(f"_dmarc.{org}")
                         if t.lower().replace(" ", "").startswith("v=dmarc1")]
            if inherited:
                rep.add("INFO", "DMARC", f"Sem DMARC próprio; herda de _dmarc.{org}.")
                records = inherited
    if not records:
        rep.add("CRÍTICO", "DMARC", "Nenhum registro DMARC — sem política para "
                "mensagens que falham SPF/DKIM; spoofing direto do domínio é viável.")
        return
    if len(records) > 1:
        rep.add("ALTO", "DMARC", "Múltiplos registros DMARC — todos são ignorados.")
    rep.dmarc = records[0]
    tags = parse_tags(records[0])
    rep.dmarc_tags = tags

    p = tags.get("p", "").lower()
    sp = tags.get("sp", "").lower()
    if p == "none":
        rep.add("ALTO", "DMARC", "p=none — modo monitoramento: e-mails forjados "
                "NÃO são bloqueados nem enviados à quarentena.")
    elif p == "quarantine":
        rep.add("BAIXO", "DMARC", "p=quarantine — forjados vão para spam. "
                "Considere p=reject.")
    elif p == "reject":
        rep.add("OK", "DMARC", "p=reject — política mais forte.")
    else:
        rep.add("ALTO", "DMARC", f"Tag p ausente/inválida ('{p}') — registro inválido.")

    if sp == "none" and p in ("quarantine", "reject"):
        rep.add("MÉDIO", "DMARC", "sp=none — subdomínios ficam sem proteção "
                "mesmo com o domínio principal em enforce.")

    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and p in ("quarantine", "reject"):
        rep.add("MÉDIO", "DMARC", f"pct={pct} — política aplicada só a {pct}% das mensagens.")

    if "rua" not in tags:
        rep.add("BAIXO", "DMARC", "Sem rua= — você não recebe relatórios agregados "
                "(sem visibilidade de abuso).")

    if tags.get("adkim", "r").lower() == "r" and tags.get("aspf", "r").lower() == "r":
        pass  # relaxed é o padrão e normal
    if "p" in tags and tags.get("v", "").upper() != "DMARC1":
        rep.add("ALTO", "DMARC", "v=DMARC1 deve ser a primeira tag.")


# --------------------------------------------------------------- DKIM ----

def estimate_rsa_bits(b64: str):
    try:
        der = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception:
        return None
    bits = (len(der) - 38) * 8
    return max(512, round(bits / 512) * 512) if bits > 0 else None


def check_dkim(d: DNS, rep: Report, selectors):
    for sel in selectors:
        recs = [t for t in d.txt(f"{sel}._domainkey.{rep.domain}")
                if "p=" in t.lower() or t.lower().startswith("v=dkim1")]
        if recs:
            rep.dkim[sel] = recs[0]

    if not rep.dkim:
        rep.add("INFO", "DKIM", "Nenhum seletor comum encontrado. Isso NÃO prova "
                "ausência de DKIM — seletores são arbitrários. Informe com --selectors.")
        return

    revoked = [s for s, r in rep.dkim.items() if not parse_tags(r).get("p")]
    for s in revoked:
        del rep.dkim[s]
    if revoked:
        rep.add("INFO", "DKIM", f"{len(revoked)} seletor(es) com chave revogada "
                f"(p= vazio; possível wildcard): {', '.join(revoked[:5])}"
                + ("..." if len(revoked) > 5 else ""))
    if not rep.dkim:
        rep.add("INFO", "DKIM", "Nenhuma chave DKIM ativa encontrada nos seletores testados.")
        return

    for sel, rec in rep.dkim.items():
        tags = parse_tags(rec)
        p = tags.get("p", "")
        if tags.get("k", "rsa").lower() == "rsa":
            bits = estimate_rsa_bits(p)
            if bits and bits < 1024:
                rep.add("ALTO", "DKIM", f"Seletor '{sel}': chave RSA ~{bits} bits "
                        "(fatorável).")
            elif bits and bits == 1024:
                rep.add("BAIXO", "DKIM", f"Seletor '{sel}': chave RSA ~1024 bits — "
                        "migre para 2048.")
            else:
                rep.add("OK", "DKIM", f"Seletor '{sel}': chave RSA ~{bits} bits.")
        else:
            rep.add("OK", "DKIM", f"Seletor '{sel}': chave {tags.get('k')}.")
        if "y" in tags.get("t", "").lower().split(":"):
            rep.add("MÉDIO", "DKIM", f"Seletor '{sel}': t=y (modo teste) — "
                    "verificadores podem ignorar falhas.")


# ------------------------------------------------------------- Driver ----

def analyze(domain: str, d: DNS, selectors) -> Report:
    domain = domain.strip().lower().rstrip(".")
    rep = Report(domain)

    if not d.exists(domain) and not d.mx(domain) and not d.txt(domain):
        rep.add("INFO", "DNS", "Domínio não resolve (NXDOMAIN ou sem registros).")
        rep.spoofable = "N/A"
        return rep

    rep.mx = [f"{pref} {host}" for pref, host in d.mx(domain)]
    if not rep.mx:
        rep.add("INFO", "MX", "Sem MX — domínio provavelmente não recebe e-mail "
                "(mas ainda pode ser usado como remetente forjado).")
    elif rep.mx == ["0 ."]:
        rep.add("INFO", "MX", "Null MX (RFC 7505) — domínio declara não usar e-mail.")

    check_spf(d, rep)
    check_dmarc(d, rep)
    check_dkim(d, rep, selectors)

    # Veredito: spoofing é bloqueado na prática se DMARC enforce (+ SPF ou DKIM).
    p = rep.dmarc_tags.get("p", "").lower() if rep.dmarc else None
    if p == "reject":
        rep.spoofable = "DIFÍCIL"
    elif p == "quarantine":
        rep.spoofable = "PARCIAL (cai em spam)"
    elif p == "none":
        rep.spoofable = "SIM (DMARC p=none)"
    else:
        rep.spoofable = "SIM (sem DMARC)"
    rep.findings.sort(key=lambda f: SEV_ORDER[f.severity])
    return rep


COLORS = {"CRÍTICO": "\033[1;31m", "ALTO": "\033[31m", "MÉDIO": "\033[33m",
          "BAIXO": "\033[36m", "INFO": "\033[37m", "OK": "\033[32m"}
RESET = "\033[0m"


def print_report(rep: Report, color: bool):
    c = (lambda s, k: f"{COLORS[k]}{s}{RESET}") if color else (lambda s, k: s)
    print("=" * 66)
    print(f" {rep.domain}")
    print("=" * 66)
    print(f" MX    : {', '.join(rep.mx) or '-'}")
    print(f" SPF   : {rep.spf or 'AUSENTE'}" + (f"  [{rep.spf_lookups}/10 lookups]" if rep.spf else ""))
    print(f" DMARC : {rep.dmarc or 'AUSENTE'}")
    print(f" DKIM  : {', '.join(rep.dkim) or 'nenhum seletor comum encontrado'}")
    print(f" Spoofing do domínio: {rep.spoofable}")
    print("-" * 66)
    for f in rep.findings:
        print(f" {c(f'[{f.severity}]'.ljust(9), f.severity)} {f.area:<5} {f.message}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Checador passivo de SPF/DMARC/DKIM.")
    ap.add_argument("domains", nargs="*", help="domínio(s) a analisar")
    ap.add_argument("-f", "--file", help="arquivo com um domínio por linha")
    ap.add_argument("-s", "--selectors", help="seletores DKIM extras (separados por vírgula)")
    ap.add_argument("-r", "--resolver", help="IP do resolver DNS (ex.: 1.1.1.1)")
    ap.add_argument("--json", action="store_true", help="saída em JSON")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    domains = list(args.domains)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            domains += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not domains:
        ap.error("informe ao menos um domínio")

    selectors = list(dict.fromkeys(
        (args.selectors.split(",") if args.selectors else []) + COMMON_SELECTORS))
    d = DNS(args.resolver)
    reports = [analyze(dom, d, [s.strip() for s in selectors if s.strip()])
               for dom in domains]

    if args.json:
        print(json.dumps([asdict(r) for r in reports], ensure_ascii=False, indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        for r in reports:
            print_report(r, color)


if __name__ == "__main__":
    main()
