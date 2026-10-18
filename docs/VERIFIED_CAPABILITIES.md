# Capacidades verificadas de ORION

Este inventario describe comportamientos ejecutables. Los documentos de referencia no constituyen plugins adicionales.

| Capacidad | Verificación | Alcance |
|---|---|---|
| Clasificación IOC offline | Pruebas de CLI/Python/MCP y de distribución instalada | IP, hash, dominio y URL; sin DNS de objetivos |
| Planificación de tickets | Fixtures de Jira/ServiceNow y rechazo de `apply` | Generación local de planes |
| Controles TLS | Pruebas de payload exacto, permisos, vigencia, cuotas y concurrencia | Laboratorio; negociación y huella, sin certificar confianza PKI |
| Herramientas MCP | Suite de superficie y transportes | 13 herramientas, 3 prompts, recursos y errores |
| Protección HTTP | Pruebas ASGI con entradas adversariales | Host/Origin, tamaño, framing y recepción lenta |
| Procesos externos | Ejecutables de prueba | Timeout, cancelación, salida y limpieza |
| Recursos | Pruebas de traversal, enlaces, cambios de rutas y presupuestos | Catálogo local de confianza |
| Instalación | Wheel/sdist ejecutados desde otro directorio | CLI, catálogo y MCP opcional |
| Normalización / triage / evidencia | Fixtures sintéticos y hashes de bytes conocidos | Resultados locales observados |

Las comprobaciones de transporte no demuestran autenticación remota, compatibilidad con cada cliente comercial ni conformidad completa con revisiones futuras de MCP. Los límites y resultados concretos de esta revisión se registran en [SECURITY_REVIEW_2026-10-18.md](SECURITY_REVIEW_2026-10-18.md).
