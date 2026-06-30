from __future__ import annotations

import dns.resolver


def query(domain: str) -> dict:
    records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SPF": [], "DMARC": []}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    resolver.timeout = 5
    try:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                records[rtype] = [str(r).strip('"') for r in resolver.resolve(domain, rtype)]
            except Exception:
                records[rtype] = []
        records["SPF"] = [txt for txt in records["TXT"] if "v=spf1" in txt.lower()]
        try:
            records["DMARC"] = [str(r).strip('"') for r in resolver.resolve(f"_dmarc.{domain}", "TXT")]
        except Exception:
            records["DMARC"] = []
        return {"source": "dns", "status": "ok", "records": records, "score_delta": 0, "evidence": "DNS records collected"}
    except Exception as exc:
        return {"source": "dns", "status": "error", "records": records, "score_delta": 0, "evidence": str(exc)}
