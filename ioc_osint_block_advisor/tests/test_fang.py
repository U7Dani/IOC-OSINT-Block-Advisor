from modules.fang import defang, normalize_domain, normalize_url, refang


def test_refang_and_defang_url():
    value = "hxxps[://]secure-wealthfront[.]com/login/"
    assert refang(value) == "https://secure-wealthfront.com/login/"
    assert defang(value) == "hxxps[://]secure-wealthfront[.]com/login/"


def test_normalizers():
    assert normalize_domain("HTTPS://WWW.Example[.]COM/path") == "example.com"
    assert normalize_url("hxxp://Example[.]com") == "http://example.com/"


def test_refang_variants_and_defanged_email():
    assert refang("hxxps://example[.]com/a") == "https://example.com/a"
    assert refang("hxxp://example(.)com/a") == "http://example.com/a"
    assert refang("example[:]443") == "example:443"
    assert refang("j.richards@copromopro[.]biz") == "j.richards@copromopro.biz"


def test_refang_bracket_colon_slash_variants():
    assert refang("hxxps[:]//ptrvc[.]net/test") == "https://ptrvc.net/test"
    assert refang("hxxp[:]//ptrvc{.}net[/]test") == "http://ptrvc.net/test"
    assert refang("user[@]example[.]com") == "user@example.com"
    assert normalize_url("hxxps[:]//ptrvc[.]net/test") == "https://ptrvc.net/test"
    assert normalize_url("hxxps[://]events[.]zoom[.]us/e/view/test") == "https://events.zoom.us/e/view/test"
