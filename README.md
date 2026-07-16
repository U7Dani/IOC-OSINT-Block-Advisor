
<p align="center">
  <img src="logo.svg" width="180" alt="IOC OSINT Block Advisor logo">
</p>
<img width="1597" height="960" alt="Captura de pantalla 2026-06-30 161125" src="https://github.com/user-attachments/assets/03b64f6a-27c3-4f39-b6ae-bc3ad2152c82" />

<h1 align="center">IOC OSINT Block Advisor</h1>

<p align="center">
  <strong>Herramienta local para analistas SOC orientada al análisis OSINT y recomendación conservadora de bloqueo de IOCs.</strong>
</p>

<p align="center">
  <em>IOC observado no significa IOC bloqueable.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python">
  <img alt="GUI" src="https://img.shields.io/badge/GUI-Tkinter-22d3ee?style=for-the-badge">
  <img alt="SOC" src="https://img.shields.io/badge/SOC-Analyst%20Tool-7c3aed?style=for-the-badge">
  <img alt="Safety" src="https://img.shields.io/badge/Blocking-Conservative-d946ef?style=for-the-badge">
</p>

---

## 🛡️ Qué es

**IOC OSINT Block Advisor** es una utilidad local en **Python 3.11 + Tkinter** diseñada para ayudar a analistas SOC durante investigaciones de **phishing**, **malware** o abuso de infraestructura.

La herramienta permite pegar contexto de investigación e IOCs observados, analizarlos, clasificarlos y generar recomendaciones justificadas.

> La herramienta **no bloquea automáticamente ningún IOC**.  
> Solo ayuda al analista a decidir qué debe bloquearse, qué debe revisarse y qué no debe bloquearse.

---

## 🎯 Principio principal

> **IOC observado no significa IOC bloqueable.**

Este proyecto nace para evitar errores operativos habituales en investigaciones SOC, por ejemplo:

- bloquear un dominio SaaS legítimo solo porque apareció en una cadena de phishing;
- bloquear un remitente legítimo usado por una plataforma real;
- bloquear dominios raíz legítimos cuando solo una URL concreta fue abusada;
- exportar indicadores dudosos como si fueran bloqueables.

La herramienta aplica una lógica conservadora: **mejor revisar que bloquear mal**.

---

## ✨ Funcionalidades destacadas

- 🧠 Clasificación conservadora de IOCs.
- 🖥️ Interfaz gráfica local tipo dashboard SOC.
- 🎨 UI moderna con estilo oscuro aurora/neón.
- 🔍 Análisis de dominios, URLs, emails, IPs y hashes.
- 🧩 Diferenciación entre infraestructura legítima y destino malicioso.
- 🧯 Evita falsos positivos en dominios SaaS conocidos.
- 🔗 Detección de URLs exactas abusadas.
- 🏁 Identificación de landings finales de phishing.
- 🧾 Generación de resumen para tickets SOC/Jira.
- 📋 Botón para copiar IOC observado.
- 🛡️ Botón para copiar únicamente el valor realmente bloqueable.
- 📤 Exportación de blocklists separadas.
- 🧪 Tests unitarios incluidos.
- 🔒 OSINT externo opcional y deshabilitado por defecto.
- 🛰️ Enriquecimiento opcional con [BBOT](https://github.com/blacklanternsecurity/bbot) (dominios/URLs/IPs/emails), con SOC Passive como modo por defecto.

---

## 🧭 Flujo de análisis

```mermaid
flowchart TD
    A[Contexto de investigación] --> C[Extractor de IOCs]
    B[IOCs observados] --> C
    C --> D[Refang y normalización]
    D --> E[Clasificador de tipo y rol]
    E --> E2[Protección de allowlists / cliente / SaaS / tenants]
    E2 --> E3[Proveedores OSINT existentes]
    E3 --> E4[Enriquecimiento BBOT opcional]
    E4 --> F[Motor de decisión conservador]
    F --> G{Decisión}
    G -->|BLOCK_DOMAIN| H[Exportar dominio bloqueable]
    G -->|BLOCK_URL_EXACT| I[Exportar URL exacta]
    G -->|BLOCK_HASH| J[Exportar hash]
    G -->|BLOCK_SENDER_EXACT| K[Exportar remitente]
    G -->|REVIEW| L[Revisión manual]
    G -->|DO_NOT_BLOCK| M[No bloquear]
    G -->|OBSERVED_ONLY| N[Observado únicamente]
```

---

## 🧠 Decisiones soportadas

| Decisión | Significado | ¿Se exporta a blocklist? |
|---|---|---:|
| `BLOCK_DOMAIN` | Dominio con evidencia suficiente para bloqueo | ✅ |
| `BLOCK_URL_EXACT` | URL concreta abusada, sin bloquear el dominio completo | ✅ |
| `BLOCK_SENDER_EXACT` | Remitente exacto con evidencia fuerte | ✅ |
| `BLOCK_HASH` | Hash malicioso o de alta confianza | ✅ |
| `REVIEW` | Requiere revisión manual del analista | ❌ |
| `DO_NOT_BLOCK` | No bloquear, normalmente infraestructura legítima | ❌ |
| `OBSERVED_ONLY` | IOC observado sin evidencia suficiente | ❌ |

Solo se exportan indicadores con decisión:

```text
BLOCK_DOMAIN
BLOCK_URL_EXACT
BLOCK_SENDER_EXACT
BLOCK_HASH
```

Nunca se exportan como bloqueables:

```text
REVIEW
DO_NOT_BLOCK
OBSERVED_ONLY
```

---

## 🧪 Ejemplo de criterio conservador

### Caso: infraestructura legítima usada en una cadena de phishing

| IOC observado | Interpretación | Decisión esperada |
|---|---|---|
| `events.zoom.us` | Plataforma legítima observada | `REVIEW` o `BLOCK_URL_EXACT` si aplica a una URL concreta |
| `meta.highspot.com` | SaaS legítimo observado | `REVIEW` |
| `login-workportal-sso.example` | Landing final de phishing | `BLOCK_DOMAIN` |
| `noreply-zoomevents@zoom.us` | Remitente legítimo observado | `DO_NOT_BLOCK` |
| `sender@example.org` | Sender sospechoso sin evidencia fuerte | `REVIEW` |

### Regla práctica

- Si el IOC pertenece a una plataforma legítima, no bloquear el dominio completo.
- Si solo una URL concreta fue abusada, priorizar `BLOCK_URL_EXACT`.
- Si es una landing final de phishing con suplantación y credenciales, recomendar `BLOCK_DOMAIN`.
- Un sender observado no se bloquea por defecto.

---

## 🖥️ Interfaz

La aplicación incluye:

- caja de contexto de investigación;
- caja de IOCs observados;
- resumen ejecutivo;
- tabla de resultados coloreada por decisión;
- detalle dinámico del IOC seleccionado;
- valor para bloqueo visible;
- acciones rápidas para copiar;
- exportación de resultados;
- barra de estado con la regla principal.

### Acciones rápidas

| Acción | Uso |
|---|---|
| `Copiar IOC` | Copia el IOC normalizado observado |
| `Copiar para bloqueo` | Copia solo el valor bloqueable si la decisión lo permite |
| `Copiar resumen para ticket` | Copia una explicación breve para pegar en Jira/ticket |

---

## 📦 Estructura del proyecto

```text
ioc_osint_block_advisor/
├── main.py
├── modules/
│   ├── fang.py
│   ├── extractor.py
│   ├── classifier.py
│   ├── decision_engine.py
│   ├── exporter.py
│   ├── osint_runner.py
│   ├── osint_bbot.py          # único punto de entrada a la integración BBOT
│   └── utils.py
├── integrations/
│   └── bbot/                  # discovery, command builder, runner, parser,
│                               # mapper, cache, health, settings (ver sección BBOT)
├── presets/
│   └── bbot/                  # presets YAML propios (soc_passive, authorized_active, ...)
├── config/
│   ├── allowlist_domains.txt
│   ├── trusted_saas_domains.txt
│   └── suspicious_keywords.txt
├── output/
│   └── .gitkeep
└── tests/
    ├── test_fang.py
    ├── test_extractor.py
    ├── test_defanged_parse_regression.py
    └── bbot/                  # tests offline de la integración BBOT (sin red, sin BBOT instalado)
```

---

## ⚙️ Instalación

### Requisitos

- Windows, Linux o macOS.
- Python 3.11 recomendado.
- Git opcional para clonar el repositorio.

### Clonar el repositorio

```powershell
git clone https://github.com/U7Dani/IOC-OSINT-Block-Advisor.git
cd IOC-OSINT-Block-Advisor\ioc_osint_block_advisor
```

### Crear entorno virtual en Windows

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\activate
py -m pip install -r requirements.txt
```

### Ejecutar la aplicación

```powershell
py main.py
```

También puedes ejecutarla usando el Python del entorno virtual:

```powershell
.\.venv\Scripts\python.exe main.py
```

---

## ✅ Validación

Desde la carpeta de la aplicación:

```powershell
py -m py_compile main.py
py -m pytest
```

Resultado esperado en la versión `v1.0.0`:

```text
19 passed
```

---

## 🔍 Fuentes OSINT soportadas

La herramienta contempla fuentes OSINT gratuitas y opcionales como:

- DNS
- RDAP
- crt.sh
- URLHaus
- ThreatFox
- MalwareBazaar
- PhishTank
- AlienVault OTX
- urlscan

### Privacidad

Las consultas OSINT externas están **deshabilitadas por defecto**.

La herramienta está diseñada para no exponer IOCs sensibles de una investigación a terceros salvo que el analista lo active explícitamente.

> Importante: nunca enviar automáticamente URLs a urlscan ni a servicios externos sin decisión consciente del analista.

---

## 🛰️ Enriquecimiento BBOT (opcional)

[BBOT](https://github.com/blacklanternsecurity/bbot) es una herramienta externa de reconocimiento OSINT / mapeo de superficie de ataque (licencia AGPLv3 - ver `NOTICE_BBOT.md`). IOC OSINT Block Advisor puede invocarla de forma **opcional** para enriquecer un IOC con infraestructura y relaciones técnicas descubiertas (subdominios, DNS, certificados, ASN, puertos, tecnologías, repositorios, etc.).

### Principio fundamental

> BBOT **descubre** infraestructura y relaciones técnicas. **Nunca decide** que un IOC es malicioso o bloqueable.

```text
IOC introducido por el analista
  → extracción y normalización
  → clasificación local
  → protección de allowlists, clientes, SaaS y tenants
  → proveedores OSINT existentes
  → enriquecimiento BBOT (opcional)
  → normalización de relaciones y evidencias
  → scoring conservador con límites por categoría
  → gates de seguridad existentes
  → decisión final del motor de decisión (sin cambios de autoridad)
```

La decisión final sigue siendo exclusivamente `BLOCK_DOMAIN` / `BLOCK_URL_EXACT` / `BLOCK_SENDER_EXACT` / `BLOCK_HASH` / `REVIEW` / `DO_NOT_BLOCK` / `OBSERVED_ONLY`, calculada por `modules/decision_engine.py`. BBOT nunca genera directamente una decisión bloqueable: como mucho, aporta evidencia capada (`integrations/bbot/mapper.py`) que ese motor evalúa con las mismas reglas conservadoras que ya existían (allowlists, gating por señal directa, etc.).

### Perfiles de seguridad

| Perfil | Contacta objetivo | Loud/Invasive | Uso |
|---|---:|---:|---|
| **SOC Passive** (por defecto) | No | No | Investigación de terceros / primer triaje |
| **SOC Passive Deep** | No | No | OSINT pasivo ampliado (CT, passive DNS, histórico, repos, cloud/ASN) |
| **Authorized Active** | Sí | Controlado | Infraestructura sobre la que tienes autorización expresa |
| **Full BBOT** | Depende | Puede | Laboratorio o análisis autorizado; selección manual de cualquier módulo/preset detectado |

Los perfiles `Authorized Active` y `Full BBOT` **exigen una confirmación explícita** en la interfaz antes de ejecutar ("Confirma que dispones de autorización expresa para analizar este objetivo") porque implican conexión directa contra el objetivo.

### Runtimes soportados

BBOT se ejecuta siempre como **proceso externo** (nunca como código importado):

- **Native**: usa el ejecutable `bbot` del sistema.
- **WSL**: ejecuta BBOT dentro de una distribución WSL desde Windows.
- **Docker**: ejecuta una imagen configurable (por defecto `blacklanternsecurity/bbot:stable`).
- **Auto** (por defecto): prueba native → WSL → Docker, en ese orden, y usa el primero que responda a `bbot --version`.

El botón **"Comprobar instalación"** de la interfaz ejecuta un diagnóstico real (`integrations/bbot/health.py`) y explica exactamente qué falta (binario no encontrado, WSL no disponible, Docker no disponible, API key ausente, etc.) en vez de un "Error" genérico.

### Descubrimiento dinámico de capacidades

Los módulos, presets y módulos de salida **no están hardcodeados**: se descubren dinámicamente ejecutando `bbot -l`, `bbot -lp`, `bbot -lo` y `bbot --version` contra la instalación real (`integrations/bbot/discovery.py`), con una caché en memoria invalidable desde el botón **"Actualizar capacidades"**. El selector **"Seleccionar módulos"** (modo Full BBOT) muestra todo lo detectado, marcando visualmente qué módulos son `active`/`loud`/`invasive`/requieren API key.

### Seguridad de la integración

- Los argumentos de BBOT se construyen siempre como **lista** (`subprocess.Popen(..., shell=False)`), nunca como cadena de shell — ver `integrations/bbot/command_builder.py` y sus tests de inyección de comandos (`tests/bbot/test_command_builder.py`).
- Objetivos, módulos, presets y módulos de salida se validan contra la instalación real antes de usarse.
- Cada escaneo tiene **timeout** configurable y puede **cancelarse** desde la interfaz; al cancelar o agotar el timeout se termina todo el árbol de procesos (sin procesos zombie).
- Existe **caché local** por objetivo/runtime/versión/perfil/módulos (nunca se mezclan resultados de perfiles distintos, ni se reutiliza un escaneo activo como si fuera pasivo).
- Por privacidad, las URLs se envían a BBOT reducidas a su dominio salvo que actives explícitamente "Incluir URL completa"; los emails se reducen siempre a su dominio.
- Ninguna API key se guarda en `config/bbot_settings.json`, en los presets versionados, en la caché, en logs ni en excepciones (ver `integrations/bbot/settings.redact`).

### Límites de scoring (nunca "más eventos = más riesgo")

El mapeador de evidencia (`integrations/bbot/mapper.py`) aplica límites máximos por categoría y deduplica semánticamente antes de sumar nada al score:

| Categoría | Límite máximo |
|---|---:|
| Reputación (malware/C2, vulnerabilidad crítica, secreto expuesto) | +40 |
| Certificado | +20 |
| Relación (takeover, phishing landing, redirección maliciosa confirmados) | +20 |
| Hosting/contexto (informativo o infraestructura compartida) | ±10 |

200 subdominios descubiertos, un puerto 443 abierto o un certificado Let's Encrypt **puntúan 0** por sí solos. Una IP en infraestructura cloud compartida (Cloudflare/Azure/AWS) nunca se exporta a blocklist (la política existente de no exportar IPs se mantiene sin cambios).

### Instalación de BBOT (acción consciente del analista)

La aplicación **no instala BBOT automáticamente**. Instálalo tú mismo si quieres usar esta integración, por ejemplo:

```powershell
# Native (con pipx)
pipx install bbot

# WSL
wsl --install
wsl -- pipx install bbot

# Docker
docker pull blacklanternsecurity/bbot:stable
```

Sin BBOT instalado, la aplicación sigue funcionando exactamente igual que antes de esta integración.

### Matriz de validación real

Esta integración se validó contra una instalación **real** de BBOT (no solo mocks). Resumen honesto de qué se probó de verdad y qué no:

| Elemento | Estado |
|---|---|
| BBOT 3.0.0 instalado (pipx, dentro de WSL2 Ubuntu-24.04; el `pip install` nativo en Windows falla porque `blasthttp` no publica wheel para Windows y requiere toolchain Rust+MSVC) | **Validado en real** |
| `bbot --version`, `-l`, `-lp`, `-lo`, `-lf`, `-lmo` interpretados por el parser | **Validado en real** (122 módulos, presets, flags y opciones reales) |
| Runtime **WSL** (detección, ejecución, cancelación, timeout, caché) | **Validado en real** |
| Runtime **Native** (Windows) | No validado (BBOT no es instalable de forma nativa en Windows sin toolchain de compilación; ver arriba) |
| Runtime **Docker** | No validado (Docker no disponible en el entorno de validación); tests solo con mocks |
| Escaneo pasivo real (perfil SOC Passive, objetivo `example.com` — dominio reservado IANA para documentación/pruebas, RFC 2606, solo consultas pasivas DNS/CT) | **Validado en real** |
| Escaneo activo real (perfil Authorized Active, laboratorio local `127.0.0.1` dentro de la misma distro WSL) | **Validado en real** |
| Relaciones padre-hijo, parser JSON, mapper (caps de score, deduplicación) | **Validado en real** (con eventos reales, no solo fixtures sintéticas) |
| Cancelación y timeout sin procesos huérfanos | **Validado en real** (verificado con `ps aux` dentro de WSL tras cancelar/timeout) |
| UI end-to-end (analizar, progreso, pestaña BBOT, cancelar, exportar) | **Validado en real** (flujo completo `analyze()` con BBOT real, sin mocks) |

Durante esta validación se encontraron y corrigieron varios problemas reales de compatibilidad con BBOT 3.x (formato de tablas en cajas Unicode en vez de texto tabulado, semántica aditiva de `flags:` en los presets, traducción de rutas Windows→WSL, y una asunción de codificación WSL que resultó incorrecta para el streaming de eventos). Ver el historial de commits de `feat/full-bbot-integration` para el detalle.

---

## 📤 Exportaciones generadas

La herramienta genera salidas separadas para facilitar el trabajo SOC:

```text
output/
├── blocklist_domains.txt
├── blocklist_urls.txt
├── blocklist_senders.txt
├── blocklist_hashes.txt
├── review_items.csv
├── full_report.md
└── ticket_summary.txt
```

Si se usó el enriquecimiento BBOT en el análisis, se generan además (solo informativos, nunca alimentan las blocklists):

```text
output/
├── bbot_summary.json        # por IOC: hallazgos, infraestructura compartida, recomendación final
├── bbot_events.jsonl        # eventos BBOT crudos (uno por línea)
├── bbot_relationships.json  # relaciones padre-hijo con tipo/directa/módulo
├── bbot_assets.csv          # activos relacionados descubiertos
└── bbot_findings.csv        # hallazgos técnicos con impacto en score
```

### Regla de exportación

Las blocklists solo contienen IOCs con decisión bloqueable:

```text
BLOCK_DOMAIN
BLOCK_URL_EXACT
BLOCK_SENDER_EXACT
BLOCK_HASH
```

Los elementos en revisión o no bloqueables quedan documentados en reportes, pero no se exportan como bloqueo.

---

## 🔒 Seguridad operacional

Este proyecto evita por diseño:

- bloqueo automático de indicadores;
- envío automático de URLs a terceros;
- exportación de IOCs dudosos como bloqueables;
- bloqueo de dominios SaaS legítimos por abuso puntual;
- bloqueo de remitentes legítimos solo por aparecer en una campaña.

### Buenas prácticas

Antes de aplicar cualquier bloqueo:

1. revisar el contexto;
2. verificar si el IOC es infraestructura legítima;
3. confirmar si se debe bloquear dominio, URL exacta, remitente o hash;
4. validar el riesgo de falso positivo;
5. documentar la decisión en ticket.

---

## 🧰 Casos de uso SOC

- Investigación de phishing.
- Análisis de cadenas de redirección.
- Separación entre infraestructura legítima y landing final.
- Revisión de remitentes observados.
- Preparación de bloqueos manuales.
- Generación de resumen para Jira o sistema de tickets.
- Documentación de IOCs observados pero no bloqueables.

---

## 🛣️ Roadmap

Mejoras previstas:

- mejorar detección de cadenas de redirección;
- ampliar fuentes OSINT gratuitas;
- enriquecer scoring conservador;
- mejorar informe SOC para tickets;
- añadir más pruebas unitarias;
- mejorar gestión de allowlists;
- empaquetado ejecutable para Windows;
- documentación visual con capturas limpias de laboratorio.

No forman parte del objetivo inmediato:

- bloqueo automático;
- integración directa con firewalls, proxy, EDR o SIEM;
- envío automático de IOCs a terceros;
- decisiones agresivas de bloqueo sin evidencia.

---

## 🧪 Filosofía de diseño

La herramienta está pensada para el trabajo diario de un analista SOC:

- rápida;
- local;
- clara;
- conservadora;
- explicable;
- útil para tickets;
- segura frente a falsos positivos.

> Bloquear mal puede romper negocio.  
> Revisar de más cuesta tiempo.  
> Esta herramienta prioriza justificar cada recomendación.

---

## ⚠️ Disclaimer

IOC OSINT Block Advisor es una herramienta de apoyo al análisis.

Las recomendaciones generadas deben ser revisadas por un analista antes de aplicar cualquier acción de bloqueo en entornos productivos.

El autor no se hace responsable del uso indebido, bloqueos incorrectos o decisiones automáticas tomadas fuera de la herramienta.

---

## 📄 Licencia

Consulta el archivo `LICENSE` del repositorio (MIT).

La integración opcional con BBOT (AGPLv3, proceso externo, no vendido en este repositorio) se documenta por separado en `NOTICE_BBOT.md`.

---

<p align="center">
  <strong>IOC OSINT Block Advisor</strong><br>
  <em>Observed IOC does not mean blockable IOC.</em>
</p>
