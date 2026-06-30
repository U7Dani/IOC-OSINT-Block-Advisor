# IOC OSINT Block Advisor

IOC OSINT Block Advisor is a local Python 3.11 tool with a Tkinter interface for SOC analysts. It helps normalize, classify, review, and document observed IOCs without applying any automatic block.

Main rule: **IOC observado no significa IOC bloqueable**.

The application is intentionally conservative: it distinguishes legitimate infrastructure observed during an investigation from truly blockable malicious destinations, and it keeps analyst review in the loop.

## Features

- IOC analysis for URLs, domains, email senders, IPs, and hashes.
- Refang/defang normalization.
- Conservative classification and decision recommendations.
- Differentiates legitimate SaaS infrastructure from final malicious destinations.
- Export of blocklists and analyst reports.
- External OSINT is optional and disabled by default.
- `Copiar IOC` button for the selected IOC.
- `Copiar para bloqueo` button only for blockable decisions.

## Privacy

The tool does not send IOCs to external services by default. Review the IOC and privacy impact before enabling external OSINT. URL submission to urlscan is disabled by default.

Do not include real SOC investigation data, customer data, API keys, tokens, or `.env` files in public commits.

## Install

```powershell
cd "ioc_osint_block_advisor"
py -3.11 -m venv .venv
.\.venv\Scripts\activate
py -m pip install -r requirements.txt
```

## Run

```powershell
py main.py
```

There is also a top-level launcher:

```powershell
py ..\main.py
```

## Validate

```powershell
py -m py_compile main.py
py -m pytest
```

## Exported Files

Exports are written under `ioc_osint_block_advisor/output/`:

- `blocklist_domains.txt`
- `blocklist_urls.txt`
- `blocklist_senders.txt`
- `blocklist_hashes.txt`
- `review_items.csv`
- `full_report.md`
- `ticket_summary.txt`

Only blockable decisions are exported to blocklists. `REVIEW`, `DO_NOT_BLOCK`, and `OBSERVED_ONLY` are not exported as block entries.

## Disclaimer

Recommendations must be reviewed by an analyst before applying any block in firewall, proxy, EDR, SIEM, or mail security tooling.
