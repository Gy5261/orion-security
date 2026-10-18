# Integraciones OSINT

ORION integra herramientas externas mediante adaptadores. No incorpora copias de sus proyectos ni instala ejecutables durante el diagnóstico.

| Plugin | Integración | Estado en el perfil controlado |
|---|---|---|
| `spiderfoot` | API HTTP local | Diagnóstico disponible; ejecución online denegada |
| `theharvester` | Subproceso | Opcional; ejecución online denegada |
| `sherlock` | Subproceso | Opcional; ejecución online denegada |
| `osint_spy` | Subproceso | Opcional; ejecución online denegada |
| `phoneinfoga` | Subproceso | Opcional; ejecución online denegada |
| `photon` | Subproceso | Opcional; ejecución online denegada |

`orion plugins describe <id> --health` muestra los parámetros y la configuración que realmente espera cada adaptador. Los tokens se suministran por variables de entorno del operador. No deben almacenarse en payloads, argumentos, ejemplos o manifiestos.

## Garantías de integración

- `argv` validado y `shell=False`; rechazo de opciones introducidas como nombres de usuario u otros valores.
- Entorno filtrado y directorio temporal por ejecución.
- Captura, archivos y duración acotados; limpieza en error, cancelación y retorno normal.
- SpiderFoot usa exclusivamente una URL HTTP(S) local validada, sin proxies ni redirecciones. `localhost` se fija a `127.0.0.1`, evitando depender de DNS para esa decisión.
- JSON de respuesta estricto y redacción de datos sensibles en errores/resultados.

Estas garantías se verifican con ejecutables ficticios, respuestas sintéticas y pruebas locales. No se contactaron servicios OSINT externos ni se certificó compatibilidad con todas sus versiones. El binario externo sigue siendo una dependencia local confiable.

El [perfil controlado](CONTROLLED_OPERATION.md) prevalece sobre las capacidades declaradas. Para clasificar indicadores sin consultar servicios, utilice `ioc_enricher` con `external_sources: false`.
