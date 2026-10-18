# Contratos y runtime de plugins

## Registro e interfaces

ORION mantiene nueve plugins incorporados y el grupo de entry points `orion.plugins`. La instalación no necesita las herramientas externas. `PluginRegistry(load_external=False)` es el valor predeterminado; descubrir extensiones Python requiere una decisión explícita del integrador local.

```bash
orion plugins list --json
orion plugins describe ioc_enricher --health
orion plugins doctor
```

`doctor` informa herramientas opcionales ausentes sin fallar la instalación. `--strict` permite que un operador exija todas las dependencias. La disponibilidad de un binario o URL configurada no prueba conectividad ni autorización.

## Ejecución desde Python

```python
from orion.plugins.core import OrionRuntime, PluginContext

result = OrionRuntime().execute(
    "ioc_enricher",
    {"iocs": ["198.51.100.4", "example.invalid"], "external_sources": False},
    PluginContext(authorization="OFFLINE-REVIEW-001"),
    timeout_seconds=10,
)
print(result.to_dict())
```

El runtime valida JSON, copia el payload, comprueba el esquema y evalúa la política antes de ejecutar. Los plugins incorporados aplican también esa política cuando se llama a `.run()` directamente; una admisión del runtime no se reutiliza para otro plugin y no consume dos veces la cuota TLS. Red, efectos externos y autorización se derivan de la operación concreta; la presencia de una clave o de una etiqueta en el manifiesto no evita los controles.

## JSON Schema soportado

El validador del runtime implementa el subconjunto de JSON Schema que declara el proyecto: tipos, propiedades requeridas, propiedades adicionales, longitudes, cantidades, patrones, límites numéricos, const/enum y combinaciones admitidas. No es un intérprete de todos los vocabularios de JSON Schema. No descarga esquemas remotos. Las assertions no implementadas, como `$ref` o `format`, se rechazan explícitamente, incluso en ramas alternativas.

La igualdad JSON distingue booleanos de números y reconoce equivalencia numérica para `uniqueItems`. Incluso los nodos sin un esquema detallado deben ser JSON válido y acotado. El validador del repositorio usa además Draft 2020-12 para comprobar los documentos de esquema publicados.

## Tiempo, cancelación y resultados

`timeout_seconds` comparte un deadline con los adaptadores y tareas paralelas. Una ejecución que supera el plazo no produce un resultado exitoso tardío. `ExecutionCancellation` permite señalizar cancelación desde otra hebra; los motores deben alcanzar un punto de control.

Los procesos externos aplican su deadline mientras esperan; se limpian en retorno normal, excepción, interrupción y cancelación. El código Python arbitrario sigue siendo confiable: la cancelación cooperativa no lo interrumpe por la fuerza.

Los resultados conservan `plugin_id`, `plugin_version`, `request_id`, `actor`, `ok`, `duration_ms`, `data`, `warnings` y `error`. Los consumidores deben comprobar `ok` y el estado de cada elemento cuando un motor produce resultados parciales.

## Adaptadores

Las entradas se convierten en una lista de argumentos validada; nunca se concatenan para una shell. La configuración de ejecutables corresponde al operador, no al payload. Se filtran variables de inyección de intérpretes/cargadores y se usan directorios temporales para ejecución y artefactos.

La captura de stdout/stderr y la recopilación de archivos están acotadas. Se rechazan enlaces, archivos especiales, JSON ambiguo y argumentos interpretables como opciones no permitidas. La redacción de secretos es defensa adicional; no convierte la salida de una herramienta en dato publicable automáticamente.

## Cambios de contrato

El manifiesto estático `skills/skills.json` se genera desde el registro y utiliza `python_runtime: "not_recorded_static_catalog"`. `python tools/validate_repository.py` compara metadata, esquemas, permisos, versiones y entry points. Un cambio debe actualizar el catálogo y sus pruebas en la misma revisión.

Mantenga APIs públicas dentro de la versión mayor. El rechazo de coerciones, traversal y entradas ambiguas es parte de la corrección de seguridad de 2.1.1. Consulte [arquitectura](../orion/ARCHITECTURE.md) y [operación controlada](CONTROLLED_OPERATION.md).
