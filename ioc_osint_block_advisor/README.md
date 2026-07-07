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

## Allowlists por capas y protección de cliente (Fluidra)

La herramienta distingue entre capas de allowlist con semánticas distintas. No es lo mismo "microsoft.com es SaaS legítimo" que "este tenant de SharePoint pertenece a Fluidra":

| Capa | Fichero | Efecto |
|---|---|---|
| Allowlist de cliente | `config/client_allowlist_domains.txt` | Protección fuerte (Fluidra, clientes/proveedores confirmados): **nunca** `BLOCK_DOMAIN` ni `BLOCK_SENDER_EXACT`. Decisión `DO_NOT_BLOCK` o `REVIEW` con riesgo de FP Alto. -80 al score. |
| Remitentes de cliente | `config/client_allowlist_senders.txt` | Remitentes protegidos (`usuario@dominio`, `@dominio` o `dominio`). Mismo efecto que la capa de cliente. |
| Tenants corporativos | `config/client_tenant_domains.txt` | Tenants SaaS legítimos del cliente (p. ej. `fluidra.sharepoint.com`). Protección de cliente; verificar cada tenant antes de añadirlo. |
| Marcas protegidas | `config/client_allowlist_keywords.txt` | No legitiman nada: sirven para detectar suplantación léxica. Un dominio NO protegido que contenga la marca (incluso con homógrafos: `flu1dra`) genera la señal fuerte `brand_impersonation` (+35). |
| Trusted SaaS | `config/trusted_saas_domains.txt` | Plataforma legítima genérica: nunca `BLOCK_DOMAIN`; `BLOCK_URL_EXACT` solo con abuso confirmado de la URL exacta. -60 al score. |
| Allowlist general | `config/allowlist_domains.txt` | Reduce score (-50) y exige evidencia excepcional; no oculta una URL exacta maliciosa confirmada. |
| Review-only | `config/review_only_domains.txt` | Nunca bloqueo automático: la decisión queda como máximo en `REVIEW` (prioridad alta si la evidencia es fuerte). |

Importante: que un dominio contenga la palabra "fluidra" no lo convierte en Fluidra. `login-fluidra-security.example` se trata como suplantación de marca y puede terminar en `BLOCK_DOMAIN`; `portal.fluidra.com` queda protegido por la allowlist de cliente.

## Umbrales y gating

Los umbrales (score ≥ 90 bloqueo, 60–89 REVIEW alta, 30–59 REVIEW, < 30 observado/no bloquear) nunca se aplican solos. Las decisiones `BLOCK_*` exigen además reglas de gating: al menos dos señales fuertes con una de ellas ligada explícitamente al IOC (`required_direct_malicious_signal`), y que el IOC no esté protegido por cliente/trusted SaaS/review-only. Los gates activos se registran en el razonamiento del analista de cada IOC.

## OSINT externo

OSINT externo está **deshabilitado por defecto**. Sin OSINT, la herramienta analiza solo con contexto, reglas locales y configuración, y lo indica explícitamente ("OSINT externo no consultado"); no inventa reputación. Si se habilita, por defecto **no se envían URLs completas a terceros**: urlhaus/threatfox/otx se consultan por dominio y urlscan/PhishTank quedan `not_checked`, salvo que se active la opción separada "Incluir URL completa en OSINT". Los veredictos se normalizan a `malicious / suspicious / clean / unknown / not_checked / error` y las fuentes consultadas se registran por IOC.

## Motor de decisión contextual (v2)

El análisis lee el contexto de la investigación frase a frase y asocia señales a cada IOC:

- **Señales fuertes** (elevan el bloqueo): landing final (+40), captura/solicitud de credenciales (+35), suplantación (+30), dominio recientemente creado (+25), phishing/portal fraudulento (+25), redirección final (+20), no relacionado con proveedor legítimo (+20), abuso confirmado (+30), formulario/portal de login (+15), autenticación SPF/DKIM/DMARC fallida (+15).
- **Señales de cautela** (reducen el bloqueo): dominio raíz SaaS confiable (-50), dominio en allowlist (-40), dominio remitente legítimo (-30), autenticación de correo válida (-25), infraestructura legítima mencionada (-25), solo observado (-20), infraestructura cloud compartida (-20).

Una señal es **directa** si la frase menciona explícitamente el IOC (o su dominio/raíz). Las decisiones `BLOCK_*` exigen score ≥ 80, al menos dos señales fuertes y al menos una directa; entre 40 y 79 el IOC queda en `REVIEW`; por debajo, `OBSERVED_ONLY` o `DO_NOT_BLOCK`.

Reglas de protección:

- Los dominios en `config/allowlist_domains.txt` o `config/trusted_saas_domains.txt` **nunca** producen `BLOCK_DOMAIN`. Una URL exacta abusada sobre esos dominios puede ser `REVIEW` o `BLOCK_URL_EXACT` si el abuso está confirmado.
- Los senders solo producen `BLOCK_SENDER_EXACT` con evidencia fuerte y explícita (abuso confirmado, spoofing, fallo de autenticación) más confirmación OSINT.
- Las IPs nunca pasan de `REVIEW` (no existe blocklist de IPs en la exportación).

Cada resultado incluye `evidence`, `positive_signals`, `negative_signals`, `score_breakdown`, `confidence`, `block_value`, `why_blockable`, `why_not_blockable` y `analyst_reasoning`, visibles en el informe completo, el CSV de revisión y el resumen para ticket.

Las blocklists exportadas siguen conteniendo únicamente decisiones `BLOCK_*`; `REVIEW`, `DO_NOT_BLOCK` y `OBSERVED_ONLY` nunca se exportan como bloqueo.
