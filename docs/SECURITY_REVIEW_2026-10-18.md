# Revisión defensiva de ORION Security — 18 de octubre de 2026

## Alcance

La revisión parte del commit `dd714dfd5e36d128a934600bb9c5a39af8b3f555` de `Gy5261/orion-security`. Abarca núcleo Python, controles, adaptadores, MCP, archivos, scripts locales, empaquetado, CI y documentación vigente. La versión de código resultante es 2.1.1; no implica una publicación en PyPI.

Se conservan los contratos de entrada principales, los nueve identificadores de plugins y las trece herramientas MCP. Los cambios rechazan representaciones ambiguas y endurecen límites previamente incompletos.

## Defectos corregidos

| Área | Problema comprobado en revisión | Corrección y evidencia |
|---|---|---|
| JSON | Validación repetida y tamaños comprobados después de serializar; claves y Unicode sin presupuesto uniforme | `jsonio.py`; regresiones de amplificación, profundidad, NaN, duplicados e enteros |
| Archivos | Comprobaciones previas sin apertura de cada padre; alias físicos publicables | `fileio.py` y catálogo; prueba de intercambio de padre por symlink y hardlink privado |
| Catálogo | Recorrido limitado sólo por archivos admitidos; fallback a un CWD con apariencia de repo; lecturas fallidas fuera del presupuesto | Presupuesto de todas las entradas, reserva de bytes incluso en error y raíz del paquete instalado |
| Aprobaciones | Rutas que no aplicaban realmente la exclusión del repositorio y alias físicos | Rutas privadas efectivas, permisos/padres y lecturas verificadas |
| Esquemas | Validación parcial de nodos libres, igualdad uniqueItems y assertions ignoradas | Validador separado, rechazo explícito y regresiones por esquema |
| Solicitudes | Objetos mutables podían cambiar entre validación y ejecución | Snapshot JSON antes de la política |
| Deadlines | Timeout general informativo, callbacks síncronos en el event loop | Presupuesto compartido, cancelación, rechazo de éxitos tardíos y pool MCP acotado |
| Procesos | Limpieza incompleta en interrupción/cancelación, captura y artefactos con bordes abiertos | Sesión/job por proceso, limpieza incondicional y lectura acotada |
| Argumentos y entorno | Valores como opciones de Sherlock y variables de inyección de intérpretes | Validadores específicos, entorno filtrado y redacción |
| MCP HTTP | Content-Length patológico, framing contradictorio, Host/Origin divergentes del SDK | Guard estricto y listas compartidas, pruebas ASGI y transportes |
| MCP errores/configuración | Excepciones con datos locales y configuración de cliente mal escapada | Frontera uniforme, validación de URLs, quoting y errores sanitizados |
| Scripts | Lecturas JSON diferentes, null type en triage, hashing potencialmente interminable | I/O compartida, manejo de null y límite a bytes de la instantánea |
| Distribución | Wheel sin documentación necesaria y build sin smoke aislado | Package data, MANIFEST.in e instalación real fuera del checkout |
| CI | Etiquetas Actions mutables, cobertura incompleta del mínimo Python y contratos divergentes | SHA completos, matriz ampliada, lint/tipos y comparación integral |

Las pruebas exactas residen en `tests/test_io_security.py`, `test_adapter_security.py`, `test_plugin_security.py`, `test_mcp_boundaries.py` y `test_packaging_contracts.py`, además de la suite previa.

## Evidencia de ejecución

La línea base original pasó **197 pruebas** en Python 3.12.14 con SDK MCP 1.30.0. Las pruebas que necesitan sockets locales se ejecutaron con permiso de loopback y guard de pytest; el sandbox inicial las bloqueaba y esos rechazos no se contabilizan como defectos del producto.

La validación integrada pasó **462 pruebas en Python 3.10.22** y **462 en Python 3.12.14**, sin fallos ni omisiones en ninguno de los dos entornos con MCP. En un entorno nuevo de Python 3.10.22 **sin MCP**, pasaron **369 pruebas**, con seis omisiones correspondientes exclusivamente al SDK opcional. Son 265 casos adicionales respecto de la línea base; no se suman las ejecuciones de distintos intérpretes como pruebas distintas.

También pasan Ruff sobre código, scripts, herramientas y tests; mypy sobre 37 archivos del núcleo tipado; compilación; validación integral de contratos; las seis comprobaciones de scripts; y las referencias de 65 documentos, sin enlaces locales rotos. La prueba de archivos en crecimiento cuenta los bytes realmente leídos, incluidas las lecturas rechazadas, y verifica que no exceden el presupuesto de la consulta.

Las versiones, comandos, tiempos y comprobaciones de instalación se registran en [validation-2026-10-18.json](validation-2026-10-18.json). El registro distingue la ejecución local de los jobs de CI, incluidos Windows y las demás versiones de Python, que requieren evidencia de sus propios runners.

## Dependencias y análisis estático

Se auditó el entorno de desarrollo instalado contra el servicio público de avisos mediante pip-audit. El primer resultado señaló pip 25.0.1 del bootstrap del entorno: doce registros correspondían a seis identificadores de aviso. Se actualizó pip y el bootstrap de CI a la rama corregida `>=26.2,<27`; la auditoría final queda registrada con su versión exacta.

Bandit se utilizó como apoyo de revisión, no como prueba de ausencia de defectos. Conserva nueve avisos de severidad baja, sin avisos medios o altos: imports/llamadas explícitas de subprocesos con `shell=False`, manejo de errores de auditoría en rutas de denegación/fallo y fallback de títulos de documentación. Se revisaron sin ocultarlos mediante supresiones generales. La función legacy de consultas IOC se restringió a los servicios HTTPS previstos, sin redirecciones/proxies y con JSON acotado.

## Límites que permanecen

- No hay sandbox de código Python hostil, límites globales de RAM/disco de binarios externos ni autenticación OAuth multiusuario.
- Windows Job Objects y rechazo de reparse points requieren validación en los jobs Windows; una prueba Linux no los demuestra.
- La cancelación de Python es cooperativa; una herramienta hostil puede eludir un grupo POSIX o generar trabajo fuera de él.
- El perfil sigue denegando OSINT online y creación de tickets; no se realizaron evaluaciones de terceros.
- TLS informa negociación/huella y no certifica confianza PKI. Las heurísticas y la clasificación IOC no demuestran vulnerabilidades.
- No se afirma conformidad con una revisión MCP posterior a la implementada por el SDK observado.

## Reproducción

Use los comandos de [DEVELOPMENT.md](DEVELOPMENT.md) y [README](../README.md). La CI conserva JUnit, versiones de dependencias, auditoría, wheel/sdist y HTML verificado. Las rutas temporales de la máquina de revisión no forman parte del contrato del proyecto.
