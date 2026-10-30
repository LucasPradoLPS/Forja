# Checador de e-mail/DNS (SPF / DMARC / DKIM)

Consulta os registros DNS públicos de um domínio e aponta configurações que permitem spoofing de e-mail (SPF ausente, DMARC em `p=none`, chaves DKIM fracas etc.).

100% passivo: só faz consultas DNS (TXT/MX/A), nada é enviado ao servidor do alvo.

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

```bash
python email_dns_check.py exemplo.com
python email_dns_check.py site1.com site2.com
python email_dns_check.py -f dominios.txt
python email_dns_check.py exemplo.com --selectors meuselector,k2
python email_dns_check.py exemplo.com --resolver 1.1.1.1
python email_dns_check.py exemplo.com --json > resultado.json
```

## O que verifica

- **SPF:** ausência, múltiplos registros, `+all`/`?all`/`~all`, limite de 10 consultas DNS, `ptr`, faixas IP amplas.
- **DMARC:** ausência, `p=none`, `sp=none`, `pct<100`, falta de `rua`, herança do domínio principal.
- **DKIM:** testa seletores comuns (e os informados em `--selectors`), chaves revogadas, RSA fraco, modo teste (`t=y`).

Limitação: seletores DKIM não podem ser listados via DNS; não encontrar nenhum não prova que o domínio não usa DKIM.

## Aviso

Use apenas em domínios seus ou com autorização para auditoria.
