"""BBOT integration layer.

BBOT (https://github.com/blacklanternsecurity/bbot) is an external,
AGPLv3-licensed OSINT/attack-surface-discovery tool. It is invoked here
strictly as an external process (native binary, WSL, or Docker container)
and never imported or vendored as source code — see NOTICE_BBOT.md.

This package only *discovers infrastructure and relationships*. It never
decides that an IOC is malicious or blockable: that authority belongs
exclusively to ``modules.decision_engine``.
"""
