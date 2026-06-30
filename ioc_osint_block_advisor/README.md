# IOC OSINT Block Advisor

Herramienta local en Python para ayudar a analistas SOC a revisar IOCs observados y convertirlos en recomendaciones seguras de bloqueo.

Regla principal: **IOC observado no significa IOC bloqueable.**

La aplicación no bloquea nada automáticamente. Normaliza IOCs, aplica refang/defang, clasifica el rol del IOC, respeta una allowlist local y genera decisiones justificadas.

## Instalación

Requisitos: Python 3.11+.

```bash
cd ioc_osint_block_advisor
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

En Windows, si `python` abre Microsoft Store o no aparece en PATH, instala Python 3.11+ desde python.org y marca la opción **Add python.exe to PATH**.

## Uso

```bash
python main.py
```

También puedes ejecutar `python main.py` desde la carpeta superior del workspace; ese archivo actúa como lanzador hacia la aplicación.

Pega el contexto de la investigación, pega los IOCs observados y pulsa **Analizar IOCs**. Las consultas OSINT externas están desactivadas por defecto porque pueden exponer IOCs a servicios de terceros.

## Exportación

El botón **Exportar resultados** genera:

- `output/blocklist_domains.txt`
- `output/blocklist_urls.txt`
- `output/blocklist_senders.txt`
- `output/blocklist_hashes.txt`
- `output/review_items.csv`
- `output/full_report.md`
- `output/ticket_summary.txt`

Las blocklists solo incluyen decisiones de bloqueo:

- `blocklist_domains.txt`: solo `BLOCK_DOMAIN`
- `blocklist_urls.txt`: solo `BLOCK_URL_EXACT`
- `blocklist_senders.txt`: solo `BLOCK_SENDER_EXACT`
- `blocklist_hashes.txt`: solo `BLOCK_HASH`

`DO_NOT_BLOCK`, `OBSERVED_ONLY` y `REVIEW` nunca se exportan a blocklists.

## Configuración `.env`

Copia `.env.example` a `.env` si quieres usar APIs opcionales:

```text
OTX_API_KEY=
URLSCAN_API_KEY=
URLSCAN_AUTO_SUBMIT=false
```

Por diseño, `URLSCAN_AUTO_SUBMIT=false` evita enviar URLs nuevas a escaneo público.

## Fuentes OSINT

- DNS con `dnspython`
- RDAP vía `rdap.org`
- crt.sh
- URLhaus
- ThreatFox
- MalwareBazaar para hashes
- PhishTank como módulo opcional no consultado en el MVP
- AlienVault OTX con API key opcional
- urlscan.io buscando scans existentes

Todas las fuentes tienen timeout y control de errores. Si una fuente falla, la aplicación continúa. Un resultado sin detección en OSINT no se interpreta como benigno.

## Decisiones

Decisiones posibles:

- `BLOCK_DOMAIN`
- `BLOCK_URL_EXACT`
- `BLOCK_SENDER_EXACT`
- `BLOCK_HASH`
- `DO_NOT_BLOCK`
- `OBSERVED_ONLY`
- `REVIEW`

La allowlist prevalece sobre el score. Dominios como `zoom.us`, `events.zoom.us`, `microsoft.com`, `google.com`, `highspot.com` y similares no se recomiendan como bloqueo de dominio completo. Si una URL concreta en una plataforma legítima se confirma como abusada, la herramienta orienta a revisión o bloqueo exacto de URL.

Un sender observado no debe bloquearse solo por aparecer en un correo sospechoso. Un dominio recién creado suma riesgo, pero por sí solo no justifica bloqueo.

## Seguridad y privacidad

La herramienta:

- No bloquea automáticamente.
- No ejecuta JavaScript.
- No descarga archivos.
- No abre adjuntos.
- No detona muestras.
- No sigue redirecciones.
- No envía URLs nuevas a urlscan por defecto.
- Avisa en la interfaz cuando se activa OSINT externo.

## Generar ejecutable

```powershell
pip install pyinstaller
.\build_exe.ps1
```

El script usa:

```powershell
pyinstaller --onefile --windowed --name IOC_OSINT_Block_Advisor --add-data "config;config" main.py
```

El ejecutable escribe los resultados en una carpeta `output` junto al `.exe`.

## Tests

```bash
pytest
```

## Limitaciones

Este MVP prioriza recomendaciones conservadoras y explicables. OSINT externo puede ser incompleto, rate-limited o no responder. OTX no debe usarse como única fuente para bloqueo. La decisión final debe validarla un analista.
