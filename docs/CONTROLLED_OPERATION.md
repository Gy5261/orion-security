# Operación controlada de ORION Security

## 1. Perímetro

El perfil se aplica a `OrionRuntime`, `orion plugins run`, `orion_run_plugin` en MCP y las llamadas directas a `.run()` de los plugins incorporados. El operador local controla la instalación, los plugins y los directorios publicados. No conceda escritura sobre el código, la aprobación o la base de cuotas a un agente que sólo deba consumir herramientas.

Las APIs Python de bajo nivel son utilidades para integraciones de confianza. Llamarlas directamente no equivale a pasar por la política del runtime. El aislamiento frente a código hostil corresponde al sistema operativo.

## 2. Matriz efectiva

| Operación | Permiso efectivo |
|---|---|
| Documentación, manifiestos y diagnóstico | Lectura local |
| Clasificar IP, dominio, URL o hash con fuentes externas desactivadas | Referencia de trabajo; sin DNS de objetivos |
| Resolver objetivos o enriquecer desde servicios externos | Denegado por el perfil |
| Preparar planes de tickets | Admitido con referencia |
| Crear tickets o modificar servicios | Denegado, incluso con flags |
| Ejecutar herramientas OSINT online | Denegado, aunque estén instaladas |
| Sonda TLS de laboratorio | Aprobación exacta, permiso de red y cuota |
| Importar plugins Python externos | Desactivado por defecto; decisión del integrador confiable |

Los metadatos describen interfaces; no conceden autorización. `health.available` sólo informa disponibilidad local de la implementación o su configuración.

## 3. Trabajo offline

```bash
orion plugins run ioc_enricher --input samples/controlled/offline-iocs.json --authorization LOCAL-CLASSIFICATION-001
```

La entrada IOC acepta hasta 500 cadenas, de 1 a 2.048 caracteres. El JSON debe cumplir el presupuesto general: 1 MiB, profundidad 32 y 20.000 nodos contando claves. Las rutas CLI leen archivos regulares; también se admite `--input -` para stdin.

Las salidas declaran si fueron sólo clasificación y si hubo consulta DNS del indicador. Un hash reconocido por longitud no demuestra que pertenezca a malware. Los resultados de cabeceras HTTP son observaciones de configuración; los scores heurísticos de hallazgos no se presentan como CVSS verificado.

## 4. Preparación de laboratorio TLS

El responsable debe verificar los activos, rutas e interfaces que autoriza. El perfil admite entre 1 y 16 destinos IPv4 literales loopback o RFC1918, de 1 a 4 trabajadores y timeout de socket entre 0,1 y 10 segundos. Rechaza DNS, IPv6, URLs, direcciones públicas y extremos terminados en 0/255.

La salida TLS informa negociación, cipher y SHA-256 del certificado DER. No valida cadena de confianza ni identidad DNS y no calcula caducidad a partir de un certificado no analizado.

`orion_request_review` comprueba el payload sin contactar destinos y devuelve su huella. No crea un permiso. El SHA-256 vincula identificador del plugin y payload exacto: cambiar un valor, agregar un valor predeterminado o reordenar una lista exige nueva revisión.

## 5. Documento de aprobación

Un revisor independiente del agente prepara el archivo a partir de `samples/controlled/approval-template.json`. La plantilla no autoriza una ejecución real. La aplicación exige exactamente estos campos:

| Campo | Condición |
|---|---|
| `schema_version` | Entero 1 |
| `authorization` | Referencia exacta, al menos 12 caracteres |
| `actor` | Etiqueta que coincide con la solicitud |
| `asset_owner`, `purpose`, `legal_basis_reference` | Referencias administrativas explícitas |
| `approved_by` | Etiqueta diferente del actor |
| `environment` | `isolated-lab` |
| `not_before`, `expires_at` | Fechas con zona, vigentes, ventana máxima de 24 horas |
| `revoked` | Booleano `false` |
| `request_sha256` | Huella exacta del plugin y payload |
| `max_uses` | Entero entre 1 y 100 |

El formato se describe en `schemas/lab-approval.schema.json`. Se rechazan claves repetidas, campos adicionales, caracteres de control y valores no finitos. Estas comprobaciones no autentican al actor ni verifican la autenticidad de documentos externos.

## 6. Archivos privados y ejecución

La aprobación y la base SQLite deben estar fuera del repositorio o paquete instalado, en rutas absolutas sin traversal, enlaces ni puntos de reanálisis. En POSIX deben pertenecer al usuario del proceso y tener permisos 600; los padres no pueden permitir escritura de otros usuarios salvo directorios compartidos con sticky bit. Los enlaces físicos también se rechazan. En Windows, el operador debe aplicar ACL adecuadas; los bits POSIX no equivalen a una auditoría de ACL.

Variables de un operador que ya dispone de aprobación revisada:

```powershell
$env:ORION_LAB_APPROVAL_FILE = 'C:\ORION-Private\approved-request.json'
$env:ORION_AUDIT_DATABASE = 'C:\ORION-Private\audit.sqlite3'
```

En POSIX se configuran las mismas variables con rutas propias. No pase el contenido de la aprobación por MCP. La solicitud, una vez configurada, usa la referencia y actor exactos:

```bash
orion plugins run tls_posture_audit --input samples/controlled/tls-request.json --authorization LAB-REFERENCE-REVIEWED-001 --actor lab-operator --allow-network
```

Los valores del ejemplo son marcadores. Sin aprobación coincidente, auditoría, vigencia y cupo, el comando rechaza la operación antes de la sonda.

## 7. Cuotas y auditoría

La reserva de uso ocurre antes de ejecutar mediante `BEGIN IMMEDIATE` de SQLite. Varias solicitudes simultáneas no pueden consumir más de `max_uses`; un UUID consumido no se reutiliza. Una operación fallida o cancelada puede consumir su cupo, evitando reintentos ilimitados.

Los eventos registran estado, plugin, UUID, etiqueta del actor y hora. No incluyen payloads, objetivos, referencias privadas ni textos de excepción. Si un registro obligatorio de inicio falla, no se ejecuta la operación. SQLite no es un registro inmutable frente al administrador; restaurar una copia también puede restaurar cuotas anteriores.

## 8. Plazos y detención

Los deadlines del runtime se propagan a workers, sockets y procesos. Los adaptadores revisan cancelación y los resultados tardíos no se aceptan como éxito. Los procesos externos se limpian al finalizar, fallar o cancelarse. La ejecución Python arbitraria sólo puede detenerse cooperativamente; para interrumpirla por fuerza se necesita un supervisor o aislamiento de proceso.

`ORION_EMERGENCY_STOP=1` bloquea nuevas ejecuciones del runtime, incluso offline. Las herramientas de documentación y diagnóstico siguen disponibles. Cambiar una variable en otra terminal no modifica el entorno de un servidor ya iniciado; la emergencia operativa debe detenerse desde su supervisor. Revocar o caducar la aprobación impide nuevas admisiones, pero no revierte trabajo ya realizado.

## 9. MCP y publicación

MCP se limita a stdio o HTTP loopback, con validación de argumentos, Host/Origin y framing. Sus errores se redactan y la concurrencia está acotada. La guía [MCP_SERVER.md](MCP_SERVER.md) detalla las reglas y transportes.

El catálogo excluye carpetas ocultas, evidencia, archivos de controles conocidos y enlaces. Limita cada recurso a 2 MiB por defecto y el recorrido a 10.000 entradas/profundidad 32. La búsqueda lee hasta 32 MiB por consulta. El filtrado por nombre no identifica todos los secretos: publique sólo documentación revisada.

## 10. Desarrollo y comprobaciones

No se necesita emitir una aprobación real para ejecutar las pruebas del repositorio. La suite genera permisos y servicios sintéticos y utiliza ejecutables ficticios. El guard de sockets de pytest permite loopback/Unix; no es una barrera de red para cualquier subproceso ajeno a las pruebas.

Consulte [arquitectura](../orion/ARCHITECTURE.md), [desarrollo](DEVELOPMENT.md) y [revisión de seguridad](SECURITY_REVIEW_2026-10-18.md) para diseño, comandos y evidencia.
