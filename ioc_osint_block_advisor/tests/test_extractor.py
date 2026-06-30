from modules.extractor import extract_iocs


def test_extracts_email_once_without_domain_duplicate():
    items = extract_iocs("", "j.richards@copromopro[.]biz")
    assert len(items) == 1
    assert items[0].refanged == "j.richards@copromopro.biz"


def test_extracts_url_ip_and_hash():
    text = "hxxps[://]login[.]workportalsso[.]com/ 8.8.8.8 d41d8cd98f00b204e9800998ecf8427e"
    values = {item.refanged for item in extract_iocs("", text)}
    assert "https://login.workportalsso.com/" in values
    assert "8.8.8.8" in values
    assert "d41d8cd98f00b204e9800998ecf8427e" in values


def test_extracts_reported_defanged_iocs_without_ipv6_parse_error():
    text = """
    Sender: servicedesk@varna-mardhika[.]com
    URL inicial: hxxps[:]//ptrvc[.]net/test
    Redirección final: Isabel[.]formulier-be[.]com
    Dominio recientemente creado: formulier-be[.]com
    """
    values = {item.refanged for item in extract_iocs(text, "")}
    assert "servicedesk@varna-mardhika.com" in values
    assert "https://ptrvc.net/test" in values
    assert "Isabel.formulier-be.com" in values
    assert "formulier-be.com" in values
