# ORION Security

Runtime de seguridad defensiva para análisis local, plugins con contratos JSON y clientes MCP. La revisión **2.1.1** refuerza las fronteras de entrada, los procesos externos, los recursos publicados y la instalación del paquete.

Se conservan el nombre de distribución `orion-hacking-etico`, los comandos `orion` / `orion-mcp`, los nueve identificadores de plugins y las trece herramientas MCP. El código base no necesita dependencias externas; MCP se instala como extra.

## Instalación

Requiere Python 3.10 o posterior. Cree un entorno aislado y use una versión mantenida del intérprete.

```bash
python -m venv .venv
```

En Linux/macOS active `source .venv/bin/activate`; en PowerShell, `.venv\Scripts\Activate.ps1`. Después:

```bash
python -m pip install --upgrade "pip>=26.2,<27"
python -m pip install -e ".[dev,mcp]"
python -m orion --version
python -m orion plugins doctor
```

Para utilizar únicamente el núcleo, `python -m pip install .` basta. Los ejecutables OSINT son opcionales y no se descargan ni ejecutan durante la instalación o el diagnóstico.

## Primera ejecución: análisis sin red

```bash
python -m orion plugins run ioc_enricher --input samples/controlled/offline-iocs.json --authorization LOCAL-CLASSIFICATION-001
python -m orion plugins describe ioc_enricher
python -m orion runtime-info --json
```

La clasificación de IP, dominio, URL o hash no hace consultas DNS cuando `external_sources` es `false` o se omite. `classification_only` y `local.dns_performed` indican qué se hizo. Los planes de Jira y ServiceNow se exportan como JSON; el perfil controlado no crea tickets.

## Capacidades y permisos efectivos

| Componente | Funcionamiento |
|---|---|
| `ioc_enricher` | Clasificación local, sin consultas externas por defecto |
| `findings_ticket_sync` | Planificación de tickets para revisión |
| `tls_posture_audit` | Negociación TLS y huella del certificado; laboratorio con aprobación exacta y cuota |
| `spiderfoot`, `theharvester`, `sherlock`, `osint_spy`, `phoneinfoga`, `photon` | Adaptadores opcionales con diagnóstico; su ejecución online está denegada por el perfil controlado |
| Recursos MCP | Lectura y búsqueda léxica acotada de documentación publicada |
| Scripts locales | Normalización de hallazgos, triage de eventos, revisión de cabeceras guardadas e inventario SHA-256 |

Un plugin instalado no queda autorizado por estar disponible. El detalle de aprobación, vigencia, cuotas y parada de emergencia está en [Operación controlada](docs/CONTROLLED_OPERATION.md).

## MCP

Para un cliente que lanza procesos locales:

```json
{
  "mcpServers": {
    "orion": {
      "command": "orion-mcp",
      "args": ["--transport", "stdio"]
    }
  }
}
```

Use la ruta absoluta al ejecutable si el cliente no hereda el entorno virtual. También se admite Streamable HTTP en loopback:

```bash
python -m orion.mcp.server --transport streamable-http --host 127.0.0.1 --port 8000
```

MCP requiere SDK `>=1.30,<2`. Se mantienen stdio, Streamable HTTP y SSE legado. El servidor valida los argumentos antes de que el SDK pueda convertir tipos, mantiene el trabajo síncrono fuera del bucle asíncrono y devuelve errores estructurados. Consulte [configuración, límites y transportes](docs/MCP_SERVER.md).

## Arquitectura

| Módulo | Responsabilidad |
|---|---|
| `orion/jsonio.py` | JSON UTF-8 con límites de bytes, profundidad, elementos y enteros |
| `orion/fileio.py` | Apertura de archivos regulares mediante descriptores; rechazo de enlaces |
| `orion/controls.py` | Política de laboratorio, aprobaciones, cuotas SQLite y auditoría mínima |
| `orion/plugins/core.py` | Contratos, registro, copia validada de solicitudes y resultados |
| `orion/plugins/execution.py` | Plazos compartidos y cancelación cooperativa |
| `orion/plugins/adapters.py`, `processes.py`, `redaction.py` | Argumentos y entorno, limpieza de procesos, captura y redacción |
| `orion/mcp/` | Configuración, transporte, validación y ejecución de callbacks |
| `orion/resources.py` | Catálogo de publicación con recorrido, lecturas y búsqueda acotados |

Las dependencias y los límites de confianza se explican en [Arquitectura](orion/ARCHITECTURE.md). El [registro de revisión](docs/SECURITY_REVIEW_2026-10-18.md) relaciona defectos corregidos con sus pruebas.

## Verificación

```bash
python tools/validate_repository.py
python -m ruff check orion tools tests .github/scripts
python -m mypy orion
python -m pytest --allow-hosts=127.0.0.1,::1 --allow-unix-socket --timeout=90
python -m build
python -m orion plugins doctor
```

Las pruebas usan fixtures, ejecutables ficticios y servicios locales. El guard de pytest restringe sockets Python; la instalación de dependencias y la auditoría de avisos de seguridad usan servicios de paquetes. El [flujo de desarrollo](docs/DEVELOPMENT.md) describe la matriz de CI y la comprobación de wheel/sdist fuera del checkout.

## Límites operativos

El operador local, el intérprete y las herramientas externas instaladas forman parte del entorno de confianza. ORION no aísla código Python hostil, no limita toda la RAM o el disco de un ejecutable externo y no autentica múltiples usuarios por OAuth. Las etiquetas de actor y las referencias de aprobación no prueban identidad; los recursos y prompts no conceden permisos.

Los deadlines interrumpen adaptadores en sus puntos de control y rechazan resultados tardíos. Python arbitrario en proceso requiere aislamiento del sistema operativo para una interrupción forzosa. El servidor HTTP se limita a loopback; Host y Origin se comprueban, pero no sustituyen autenticación.

Las guías actuales enlazadas aquí prevalecen sobre los informes históricos de `docs/` y el contenido metodológico de `orion/references/`. Esos archivos se conservan como material de consulta, no como evidencia de capacidades ejecutadas.
