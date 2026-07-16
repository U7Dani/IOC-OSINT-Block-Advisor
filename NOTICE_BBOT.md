# Aviso de licencia: integración con BBOT

IOC OSINT Block Advisor se distribuye bajo licencia **MIT** (ver `LICENSE`).

Este proyecto incluye una integración **opcional** con
[BBOT](https://github.com/blacklanternsecurity/bbot) (Black Lantern
Security), una herramienta de reconocimiento OSINT / mapeo de superficie de
ataque distribuida bajo licencia **GNU AGPLv3**.

## Qué significa esto en la práctica

- **BBOT no está incluido, vendido ni empaquetado dentro de este
  repositorio.** No se copia, adapta ni redistribuye ningún fichero fuente
  de BBOT en `ioc_osint_block_advisor/`.
- BBOT se invoca exclusivamente como **proceso externo**: un binario
  instalado en el sistema (`native`), dentro de una distribución **WSL**, o
  mediante una **imagen Docker** oficial/configurable. Toda la
  comunicación ocurre a través de su interfaz de línea de comandos
  (`subprocess`) y de la salida `--json` que BBOT emite a stdout.
- Los ficheros en `ioc_osint_block_advisor/presets/bbot/*.yml` son
  **artefactos de configuración propios** de IOC OSINT Block Advisor,
  escritos para el esquema de presets YAML público de BBOT (selección de
  flags/módulos/salidas). No contienen código fuente de BBOT.
- El código Python bajo `ioc_osint_block_advisor/integrations/bbot/` es
  **código original de este proyecto** (licencia MIT) que sabe cómo
  *hablar* con BBOT (construir su línea de comandos, leer su salida JSON,
  interpretar sus eventos) — no reimplementa ni deriva de la lógica interna
  de BBOT.
- La aplicación **funciona íntegramente sin BBOT instalado**: si no se
  detecta ningún runtime válido (nativo, WSL o Docker), la integración se
  desactiva de forma explícita y el resto de la herramienta (extracción,
  clasificación, OSINT propio, motor de decisión, exportación) continúa
  operando sin cambios.

## Atribución

BBOT es un proyecto de Black Lantern Security, licenciado bajo la GNU
Affero General Public License v3.0. Si usas, redistribuyes o modificas
BBOT directamente, debes cumplir los términos de la AGPLv3 para ese
software — algo independiente de los términos MIT de este repositorio.
Repositorio oficial: https://github.com/blacklanternsecurity/bbot

## Separación de responsabilidades (por qué importa aquí)

BBOT **descubre infraestructura y relaciones técnicas**. Nunca decide, por
sí mismo, que un IOC es malicioso o bloqueable: esa decisión final
(`BLOCK_DOMAIN`, `BLOCK_URL_EXACT`, `BLOCK_SENDER_EXACT`, `BLOCK_HASH`,
`REVIEW`, `DO_NOT_BLOCK`, `OBSERVED_ONLY`) sigue siendo responsabilidad
exclusiva de `modules/decision_engine.py`, con los mismos gates y límites
conservadores que ya existían antes de esta integración. Ver la sección
"Enriquecimiento BBOT" del README para más detalle.
