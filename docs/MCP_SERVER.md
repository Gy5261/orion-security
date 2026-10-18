# Servidor MCP de ORION Security

## Instalación y transportes

Instale `python -m pip install ".[mcp]"`; el extra exige `mcp>=1.30,<2`. La instalación básica permite inspeccionar configuración sin importar el SDK, pero iniciar el servidor necesita ese extra.

```bash
orion-mcp --transport stdio
orion-mcp --transport streamable-http --host 127.0.0.1 --port 8000
orion-mcp --transport sse --host 127.0.0.1 --port 8000
orion-mcp --print-config
```

`--host ::1` publica un endpoint IPv6 con corchetes en el URI. `--allow-remote` se mantiene por compatibilidad del parser, pero no habilita un servicio remoto. No hay autenticación OAuth multiusuario implementada.

## Superficie pública

| Herramienta | Resultado |
|---|---|
| `orion_mcp_capabilities` | Capacidades y transporte observado |
| `orion_client_config` | Configuración validada de clientes |
| `orion_list_plugins` | Manifiesto de plugins y diagnóstico opcional |
| `orion_get_plugin` | Contrato de un plugin |
| `orion_doctor` | Disponibilidad de implementaciones y dependencias |
| `orion_run_plugin` | Ejecución según la política controlada |
| `orion_search_resources` | Búsqueda literal de documentación |
| `orion_resource_links` | Bloques MCP `ResourceLink` |
| `orion_read_resource` | Contenido de texto publicado |
| `orion_read_resource_content` | Contenido tipado; base64 para binarios |
| `orion_control_status` | Estado de controles sin rutas privadas |
| `orion_request_review` | Preflight y huella; no concede autorización |
| `orion_protocol_audit` | Versión del SDK, protocolo observado y límites |

Se conservan los prompts `authorized_security_workflow`, `mcp_integration_guide` y `controlled_lab_workflow`. Los recursos estáticos y plantillas enlazan manifiestos, controles, contratos y archivos del catálogo.

## Validación y concurrencia

Los argumentos se validan con tipos JSON reales antes de la conversión del SDK: `"false"` no es un booleano y una cadena que contiene JSON no equivale a un objeto. Se rechazan campos desconocidos y entradas fuera de presupuesto.

Los callbacks síncronos se ejecutan en un pool acotado, para que un plugin no bloquee el bucle asíncrono de MCP. Se admiten 8 workers y 64 trabajos pendientes/en ejecución. La saturación produce un error explícito. La cancelación se transmite al runtime y a los adaptadores mediante un token compartido.

Los errores de herramientas usan `isError` y un mensaje sanitizado. Las excepciones de lectura, diagnóstico y ejecución no devuelven rutas del operador ni valores sensibles del entorno. Los resultados también tienen presupuesto de serialización UTF-8.

## Frontera HTTP

El guard y la protección DNS-rebinding del SDK usan las mismas listas exactas de Host/Origin, incluyendo IPv6. CORS opcional requiere orígenes HTTP(S) concretos, sin credenciales, rutas ni comodines. Origin no autentica programas que ya se ejecutan en el equipo.

Se rechazan cabeceras de seguridad duplicadas, longitud contradictoria, combinación Content-Length/Transfer-Encoding, cuerpos en métodos que no los admiten, cuerpos excesivos y carga demasiado lenta. Límites: 1 MiB de cuerpo, 32 KiB de cabeceras, 128 cabeceras, 4.096 fragmentos y 10 segundos de recepción. Se admiten como máximo 64 solicitudes HTTP simultáneas, incluidos streams; al saturarse se devuelve 503 antes de almacenar otro cuerpo. Los streams de respuesta no se almacenan completos en el guard.

Los POST atraviesan el parser JSON estricto compartido antes del SDK: se rechazan UTF-8 inválido, claves repetidas, números no finitos y estructuras fuera del presupuesto.

## Frontera stdio y salidas

El adaptador `orion.mcp.stdio` lee cada mensaje con un límite de 1 MiB más el delimitador. No usa una lectura de línea ilimitada. Aplica la misma validación UTF-8 y JSON estricta antes de entregar el mensaje al SDK; un documento inválido sigue la ruta de error de parseo sin reenviar su contenido privado. Si una línea excede el límite, se cierra la conexión sin drenar una entrada potencialmente interminable ni interpretar su cola como otra solicitud.

El SDK mantiene la negociación, JSON-RPC y las notificaciones de cancelación. Las respuestas de herramientas, recursos y prompts se limitan a 8 MiB; el cálculo incluye bytes UTF-8 y las representaciones estructurada y textual de los resultados. Stdio dispone además de una última cota de 8 MiB + 4 KiB para la trama serializada y escribe exclusivamente mensajes del protocolo en stdout. Los diagnósticos corresponden a stderr. Un archivo permitido por el catálogo puede superar el presupuesto MCP después de codificarlo en base64 o duplicar su texto en `structuredContent`; en ese caso debe publicarse una versión menor.

## Recursos y confianza

`ORION_RESOURCE_ROOT` define el árbol documental que el operador autoriza a publicar. En instalación fuente se usa el repositorio; en wheel, los datos empaquetados de `orion`. Un directorio de trabajo ajeno no se adopta automáticamente.

No se publican enlaces, rutas privadas de controles, directorios ocultos ni carpetas reservadas de evidencia. El contenido recuperado sigue siendo dato no confiable; no autoriza comandos ni cambios de política.

## Pruebas y compatibilidad

La suite comprueba las trece herramientas, prompts, recursos, errores y round trips de stdio, Streamable HTTP y SSE. HTTP se prueba con las combinaciones de estado y formato de respuesta, más ASGI en memoria para framing, IPv6 y CORS.

La revisión usa la familia de SDK 1.x y su negociación `initialize`; no anuncia conformidad con MCP 2026-07-28 ni soporte de extensiones que no implementa. Consulte `orion_protocol_audit` para el estado del entorno real.

Véase [Arquitectura](../orion/ARCHITECTURE.md), [operación controlada](CONTROLLED_OPERATION.md) y [evidencia de revisión](SECURITY_REVIEW_2026-10-18.md).
