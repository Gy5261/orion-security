# Desarrollo, pruebas y distribución

El runtime base de ORION conserva el contrato de instalación con Python >= 3.10
y no necesita dependencias de terceros. El servidor MCP es un extra explícito:
`mcp>=1.30,<2`. El nombre de distribución sigue siendo `orion-hacking-etico` para
mantener la compatibilidad de la serie 2.x; el repositorio es
[`Gy5261/orion-security`](https://github.com/Gy5261/orion-security).

## Preparar el entorno

Leer [AGENTS.md](../AGENTS.md) antes de modificar código. Desde la raíz del
repositorio, en Linux o macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade "pip>=26.2,<27"
python -m pip install -e ".[dev,mcp]"
python -m pip check
```

En PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade "pip>=26.2,<27"
python -m pip install -e ".[dev,mcp]"
python -m pip check
```

Para uso del runtime sin MCP basta `python -m pip install .`. El archivo
`requirements.txt` apunta a ese mismo proyecto; las dependencias se mantienen
solamente en `pyproject.toml`. No se instalan herramientas OSINT externas como
parte de estos comandos. `orion plugins doctor` informa cuáles faltan sin
considerar su ausencia un fallo del runtime; `--strict` sí exige tenerlas.

## Verificaciones antes de proponer cambios

```bash
python -m compileall -q orion tools tests .github/scripts
python -m ruff check orion tools tests .github/scripts
python -m mypy orion
python tools/validate_repository.py
python -m pytest --allow-hosts=127.0.0.1,::1 --allow-unix-socket --timeout=90
python orion/scripts/run_skill_sanity.py
python -m orion plugins doctor
python -m build
```

Ruff cubre también los scripts heredados. Mypy comprueba los módulos del runtime
y sus APIs; la configuración mantiene la excepción histórica de comprobación
de tipos para `orion.scripts.*`. Esa excepción no elimina las pruebas, el lint
ni la compilación de los scripts. Las advertencias de pytest se muestran.

`validate_repository.py` importa el código del checkout actual, incluso cuando
el entorno tiene una distribución anterior instalada. Verifica:

- Versiones, nombre de distribución, Python mínimo y funciones de entrada.
- Los nueve plugins incorporados y sus requisitos de autorización.
- El esquema del manifiesto y los esquemas de entrada/salida de los plugins.
- Igualdad completa entre el catálogo estático y la metadata del runtime.
- JSON acotado, sin claves duplicadas ni números no finitos.
- Llamadas a procesos sin shell y con timeout explícito en `subprocess.run`,
  incluyendo nombres importados mediante alias.
- Disponibilidad de los recursos y rechazo de rutas que salen de su raíz.

El análisis AST detecta patrones conocidos; no demuestra que un programa
arbitrario sea seguro y no reemplaza la revisión de código. Las dependencias
del validador son de desarrollo, no del runtime base.

## Pruebas sin destinos externos

Los datos son sintéticos y los adaptadores de herramientas se sustituyen por
ejecutables temporales o respuestas controladas. Ninguna prueba debe contactar
servicios reales. Los transportes MCP usan procesos locales y conexiones a
`127.0.0.1`; el loopback debe estar permitido en el entorno de ejecución.

`pytest-socket` restringe los sockets del proceso de pruebas a loopback;
`--allow-unix-socket` permite la comunicación interna de los bucles asíncronos.
Este guard no es un cortafuegos para subprocesos ni controla código ejecutado
fuera del proceso Python de pytest. Los adaptadores deben seguir usando
fixtures, incluso cuando la prueba lleva esas opciones. `pytest-timeout` limita
cada prueba a 90 segundos para que una integración bloqueada produzca un fallo
visible en lugar de agotar el job completo.

Para comprobar la instalación opcional, crear otro entorno limpio e instalar
`.[dev]`, sin `[mcp]`. La misma suite debe ejecutar las pruebas del runtime y
marcar como omitidas las que necesitan el SDK. No se omiten fallos del SDK
cuando éste sí está instalado. La CI comprueba ambos estados.

## Mantener el catálogo estático

Después de cambiar metadata, permisos o esquemas, regenerar el catálogo desde
el runtime y quitar cualquier dato dependiente de la máquina:

```bash
python - <<'PY'
import json
from pathlib import Path
from orion.plugins.core import PluginRegistry

manifest = PluginRegistry(load_external=False).manifest()
manifest["runtime"]["python_runtime"] = "not_recorded_static_catalog"
Path("skills/skills.json").write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)
PY
python tools/validate_repository.py
```

Actualizar `pyproject.toml`, `orion.__version__` y el catálogo en el mismo cambio
de versión. Los puntos de entrada declarados deben seguir apuntando a las
clases realmente registradas. No basta con conservar sus identificadores.

## Qué incluye una distribución

El wheel incluye los módulos Python y una lista explícita de recursos públicos
bajo `orion/`: guías Markdown, referencias, playbooks, configuración del agente
y los scripts de instalación Bash/PowerShell. No copia el directorio de trabajo
del usuario ni incluye bases de auditoría o credenciales. El HTML del sitio se
genera y verifica por separado; no es una dependencia del runtime.

`MANIFEST.in` añade al sdist documentación, esquemas, catálogos, muestras, pruebas
y herramientas para revisar el código fuente. `python -m build` genera primero
ese sdist y construye el wheel desde él; esto detecta archivos omitidos que una
compilación directa desde el checkout podría ocultar.

La CI hace tres verificaciones de instalación reales:

1. Instala el wheel base con `--no-index --no-deps` en un entorno nuevo, sin MCP.
2. Instala el sdist y ejecuta sus comandos fuera del checkout.
3. Resuelve el extra `[mcp]` del wheel y comprueba el servidor instalado.

En los tres casos ejecuta `.github/scripts/smoke_install.py` con `python -I`.
Ese modo impide que `PYTHONPATH` o la carpeta del checkout oculten un paquete
incompleto. El smoke comprueba los comandos `orion` y `orion-mcp`, el doctor,
los recursos distribuidos y una clasificación IOC sin DNS. También verifica
que una carpeta de trabajo con `README.md` y un subdirectorio `orion` no se
publique automáticamente como catálogo. Cuando el SDK está disponible, crea
el servidor y comprueba su lista real de herramientas sin abrir un puerto.

Ejemplo local para el wheel base, después de `python -m build`:

```bash
python -m venv /tmp/orion-wheel-check
/tmp/orion-wheel-check/bin/python -m pip install --no-index --no-deps dist/*.whl
/tmp/orion-wheel-check/bin/python -I .github/scripts/smoke_install.py --expect-mcp absent
```

Usar una carpeta nueva para cada verificación. Para repetir un build sin
descargas, preparar antes las dependencias de `[build-system]` y ejecutar
`python -m build --no-isolation`. Esto cambia dónde se obtienen las dependencias
de compilación; no equivale a resolverlas o auditarlas de nuevo.

El entorno temporal del smoke base usa el pip incluido por `ensurepip` para
instalar únicamente el wheel local, sin resolver dependencias ni contactar un
índice. El informe muestra esa versión de pip; el smoke no declara auditado
su bootstrap. Los entornos de desarrollo y los jobs que resuelven paquetes
actualizan pip a `>=26.2,<27` antes de instalar dependencias.

## Contrato de CI

| Job | Entorno configurado | Qué comprueba |
| --- | --- | --- |
| `quality` | Ubuntu 24.04, Python 3.12 | Compilación, lint, tipos, contratos, scripts y sitio HTML |
| `test` | Ubuntu 24.04, Python 3.10/3.12/3.14/3.15 | Suite completa con SDK MCP |
| `test` | Windows 2025, Python 3.12/3.15 | Suite completa y bootstrap PowerShell sin instalar herramientas |
| `core` | Ubuntu 24.04, Python 3.10 | Runtime y pruebas con SDK MCP ausente |
| `package` | Ubuntu 24.04, Python 3.12 | Build e instalaciones independientes de wheel/sdist |

Esta tabla describe la configuración, no certifica una ejecución. La evidencia
para una revisión concreta es su resultado de Actions y sus artefactos. Una
prueba local en Python 3.12 no valida por sí sola Python 3.15 ni Windows. Se
conservan XML de pruebas, dependencias resueltas y distribuciones durante 14 días.

Las acciones de terceros se fijan a commits SHA completos, con la versión como
comentario legible. Los workflows sólo necesitan `contents: read`; el checkout
no guarda credenciales Git. Dependabot propone actualizaciones de dependencias
y acciones para revisión, sin fusionarlas automáticamente.

La revisión de dependencias es un workflow separado: se activa al cambiar los
archivos de dependencias o manualmente. Resuelve las dependencias reales y
consulta avisos de vulnerabilidad con `pip-audit --strict`. Audita los paquetes
de terceros; el código local de ORION se evalúa mediante sus pruebas. No tiene
excepciones de vulnerabilidad preconfiguradas. Este job necesita acceso al
índice y al servicio de avisos; su resultado no es una prueba del código de ORION
ni una garantía de ausencia de vulnerabilidades desconocidas.

## Referencias de implementación

- [Setuptools: inclusión de archivos de datos](https://setuptools.pypa.io/en/latest/userguide/datafiles.html).
- [PyPA build: construcción de wheel y sdist](https://build.pypa.io/en/stable/).
- [GitHub Actions: uso seguro de acciones](https://docs.github.com/en/actions/reference/security/secure-use).
- [pytest-socket: límites y opciones](https://github.com/miketheman/pytest-socket).
- [pip-audit: uso y alcance](https://github.com/pypa/pip-audit).
