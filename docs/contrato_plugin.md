# Contrato de plugin de los recolectores (#13)

Todos los recolectores OSINT (#14 a #20) cumplen este contrato, y el orquestador (#22) solo habla con ellos a través de él. Así se puede agregar una fuente sin tocar el orquestador, que es lo que pide el reto con «módulos integrables como plugins independientes». El código está en `cirdan/recolectores/contrato.py` y las pruebas en `pruebas/test_contrato.py`.

## Qué expone cada recolector

Cada recolector es un módulo de `cirdan/recolectores/` con tres cosas:

| Nombre | Qué es |
|---|---|
| `FUENTE` | El código de su fila en `data_sources`, por ejemplo `ct_logs` |
| `crear_cliente(modo, dominio)` | Su cliente para `vivo`, `grabar` o `reproducir` |
| `recolectar(dominio, cliente=None, ahora=None, propios=())` | Devuelve un `Resultado`. `propios` son los otros dominios de la misma empresa |

Además se registra en `REGISTRO` de `cirdan/recolectores/__init__.py`, y `cargar(fuente)` devuelve su módulo. Hoy están `ct_logs` (crt.sh, #14) y `ejemplo`, que no consulta nada y sirve para probar el orquestador sin red.

## Esquema del resultado

**Resultado:** `dominio`, `fuente`, `estado` (`succeeded` o `failed`), `consultas` (entero, peticiones hechas con reintentos), `error` (texto), `avisos` (lista de textos), `activos` y `hallazgos`. Un resultado `failed` no trae activos ni hallazgos. Todo tiene que poder guardarse como JSON y sin el carácter nulo, que Postgres no acepta.

**Activo**, que va a la tabla `assets`:

| Campo | Regla |
|---|---|
| `tipo` | `domain`, `subdomain`, `ip`, `service`, `certificate` o `email`, igual que `assets.asset_type` |
| `valor` | El nombre, la IP, `ip:puerto/protocolo`, el correo o la huella del certificado. Los nombres, las IP y los correos tienen que ser válidos. No se repite con el mismo tipo |
| `atributos` | Va a `assets.attributes`. Los tipos `ip`, `service` y `certificate` llevan `host` (o `hosts`, si son varios nombres) con nombres válidos para el filtro de alcance. Sin eso no cumplen el contrato |

**Hallazgo**, que va a la tabla `findings`:

| Campo | Regla |
|---|---|
| `codigo` | El código de su regla (`scoring_rules.code`). Tiene que existir en el catálogo (#30) |
| `severidad` | La severidad base de su regla: `critical`, `high`, `medium` o `low`. El motor de score la puede subir (#29) |
| `activo` | El valor del activo al que pertenece: el dominio o uno de los activos del mismo resultado |
| `titulo` | En español y en lenguaje simple. También va en `evidencia['title']`, porque la base guarda ahí el título |
| `evidencia` | Lo que prueba el hallazgo. Nunca contraseñas, tokens completos ni datos de brechas más allá del hecho |
| `caracteristicas` | Las 4 del reto, que usa el clasificador (#33, #34). Ver la tabla de abajo |
| `huella` | sha256 en hexadecimal, estable entre escaneos. #23 la guarda en la evidencia |
| `clave` | Opcional. Distingue hallazgos del mismo código sobre el mismo activo, por ejemplo cada dominio parecido, un CVE o una brecha. #23 calcula `findings.fingerprint` como SHA-256 del código, el `asset_id` y el CVE, la brecha o esta clave, así que dos hallazgos con el mismo código, activo y clave son el mismo |

**Características del reto:**

| Campo | Valores |
|---|---|
| `tipo` | Código corto en minúsculas con guion bajo, por ejemplo `certificado_vencido` o `spf_faltante` |
| `antiguedad_dias` | Entero de 0 o más: días desde que empezó la exposición o desde que se vio por primera vez |
| `exposicion` | `directa` si el activo responde en internet (un servicio o un panel), `publica` si es un dato público (un certificado, un registro DNS, una brecha o un repositorio) |
| `sensibilidad` | `baja`, `media` o `alta`, según lo que expone |

El hallazgo de ejemplo del contrato de API (#21) debe traer `caracteristicas` con estos mismos campos y valores. Cuando #21 esté en el repo, hay que enlazar aquí su archivo.

## Filtro de alcance

Solo se aceptan activos del dominio autorizado:

- `domain` y `subdomain`: el dominio o un subdominio suyo. `acme-demo.mx.evil.com` y `xacme-demo.mx` quedan fuera.
- `email`: su dominio está en el alcance.
- `ip`, `service` y `certificate`: su `host` (o alguno de `hosts`) está en el alcance.

Lo que queda fuera se descarta, junto con los hallazgos que le pertenecen, y queda un aviso. Un hallazgo de dominio parecido pertenece al dominio de la empresa, y el dominio parecido solo va en la evidencia, así que no se descarta.

## Qué hace el orquestador con cada recolector

El orquestador llama a `ejecutar(recolector, dominio, modo, ahora, propios, codigos)`, nunca a `recolectar()` directo. `ejecutar()`:

1. Si el dominio no es un nombre válido, la fuente queda en `failed` sin llamar al recolector. Si es válido, crea el cliente del modo pedido y llama a `recolectar()` con el dominio autorizado, en minúsculas y sin punto final.
2. Si el recolector lanza cualquier excepción, devuelve un resultado `failed` con el error. El escaneo sigue con las demás fuentes.
3. Revisa el resultado con `validar()` contra este esquema y, si se le pasan, contra los códigos del catálogo. También revisa que sea del dominio autorizado y de la fuente del recolector, y que se pueda guardar como JSON. Si no cumple, la fuente queda en `failed` con los primeros incumplimientos en el error.
4. Aplica el filtro de alcance.

## Reintentos

Hay dos niveles:

- **Dentro de una corrida**, para fallas de segundos como un 502 pasajero: `con_reintentos()` hace hasta 3 intentos, con esperas de 5 y 15 segundos entre ellos. Un error HTTP 4xx, salvo 408 y 429, no se reintenta y lo interpreta el recolector, porque la fuente sí respondió: un 404 de HIBP significa «sin brechas». crt.sh sigue esta misma regla en su cliente.
- **Entre corridas**, en `scan_source_runs`: `siguiente_estado()` da el `status`, el `attempt` y el `next_retry_at`.

| Corrida | Resultado | Queda en |
|---|---|---|
| attempt 0 | failed | `retrying`, attempt 1, otra vez en 1 minuto |
| attempt 1 | failed | `retrying`, attempt 2, en 5 minutos |
| attempt 2 | failed | `retrying`, attempt 3, en 25 minutos |
| attempt 3 | failed | `failed`: el escaneo termina como `partial` (#23) |
| cualquiera | succeeded | `succeeded` |

## Respuestas grabadas

La clase `Grabadora` guarda y reproduce las respuestas de una fuente para un dominio en `cirdan/recolectores/respuestas_grabadas/<recolector>/<dominio>/`. Cada respuesta es un archivo `{grabado, consulta, datos}`. La fecha va dentro del archivo porque git y las copias cambian la del sistema.

| Modo | Qué hace |
|---|---|
| `vivo` | Consulta la fuente y no toca el disco |
| `grabar` | Consulta y guarda. Con `nueva`, vacía la carpeta y marca el inicio con la primera respuesta válida, así una grabación fallida deja intacta la anterior. Con `completar`, reutiliza lo grabado desde ese inicio. `crear_cliente('grabar', dominio)` empieza una grabación nueva |
| `reproducir` | Solo lee del disco. Si falta una respuesta, lanza `SinGrabacion`. El recolector puede tomarla como aviso, como hace crt.sh con las variantes, pero si llega a `ejecutar()` la fuente queda en `failed` igual que con cualquier otra excepción |

Las pruebas de cada recolector usan respuestas grabadas o un transporte simulado, nunca la red. El día anterior a cada sesión se graba el dominio de prueba como respaldo de la demo. En crt.sh se usa `python -m cirdan.recolectores.crtsh <dominio> --grabar`.

## Cómo agregar un recolector

1. Su fila en `data_sources` con su código.
2. El módulo en `cirdan/recolectores/` con `FUENTE`, `crear_cliente()` y `recolectar()`, que usa `Grabadora` para sus respuestas.
3. Su línea en `REGISTRO`.
4. Una prueba sin red que compruebe `validar(resultado, codigos=<los del catálogo>) == []`.
5. Los títulos en español, y nada que no sea observación pasiva.

## Lo que no es de este contrato

- La limpieza de datos y el límite diario por fuente son de #13b.
- La normalización, la deduplicación entre fuentes y el guardado en la base son de #23.
