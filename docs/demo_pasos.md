# Pasos de la demo v0.2

Demo de la sesión S12 con el socio formador, el 30 oct 2026, sobre la v0.2 (etiqueta en `main`). Dura 11 minutos en 9 partes. La columna Termina es el minuto acumulado en el que esa parte debe acabar. Si una parte se pasa de su minuto, se usa su plan B y se sigue con la siguiente.

Las cuentas del portal y cómo pasar el MFA están en [`cuentas_de_prueba.md`](cuentas_de_prueba.md). Aquí no van contraseñas ni códigos.

| # | Parte | Quién | Min | Termina | Tarjetas | Qué se ve | Plan B |
|---|---|---|---|---|---|---|---|
| 1 | Seguimiento de los acuerdos de S10 | Ernesto | 1:15 | 1:15 | RC-66, RC-43, RC-60, RC-55, RC-49, RC-54, RC-91 | Lámina con los 5 compromisos de S10 y cómo van. Base en PostgreSQL con datos reales (migraciones 003 y 005 a 010). Más de 600 pruebas automáticas, con el CI de RC-43 desde el 29 oct. Cada escaneo guarda sus hallazgos y su score desde el 28 oct (RC-55 y RC-60). Shodan hecho. Have I Been Pwned y hosting para el 6 nov | Es lámina |
| 2 | Dominio de prueba autorizado | Germán | 0:45 | 2:00 | RC-36, RC-38, RC-151, RC-42, RC-165 | En el portal, con `admin@olmardo.com` y MFA: olmardo.com con autorización vigente y TXT verificado. Lo sembrado en Grupo Olmardo, empresa ficticia: certificados de reservas, camaras y eventos, SPF sin DMARC y una clave falsa `CIRDAN_FAKE_` en su GitHub | Capturas de la carta firmada y del portal |
| 3 | Escaneo real desde el portal | Israel | 1:30 | 3:30 | RC-51, RC-17, RC-58, RC-55, RC-60 | 'Escanear ahora' en olmardo.com. El orquestador revisa carta y TXT y consulta en vivo crt.sh con Cert Spotter, DNS, GitHub, Shodan InternetDB y RDAP. El botón sigue el escaneo y al terminar el portal se refresca con los hallazgos y el score que guardó. Es el único escaneo en vivo de la sesión | Si en 20 s no queda en cola, o a las 3:30 sigue corriendo, se pasa a la parte 4, que no usa red |
| 4 | Hallazgos reales de olmardo.com en las 4 categorías | Ernesto | 2:00 | 5:30 | RC-47, RC-184, RC-48, RC-50, RC-49, RC-166, RC-45 | Terminal con `--reproducir` dentro de `cirdan-api`, sin red, con la grabación de crt.sh del 29 oct. Infraestructura: eventos.olmardo.com 'vence en 1 día' y el puerto 50000, que InternetDB trae del dueño anterior de la IP de camaras (todavía no ve el 8080 de la VM). Identidad digital: el correo de la empresa en GitHub. Configuración: sin DMARC. Fugas de datos: la clave falsa, crítica, sin mostrar su valor. Al final, registrador y vencimiento del dominio por RDAP. Si el escaneo de la parte 3 ya terminó, se cierra con los hallazgos de olmardo.com en el portal | Captura de eventos en Cert Spotter y la prueba sin red del por vencer de `test_crtsh` |
| 5 | Score, ML y SHAP en frases | Emilio | 2:15 | 7:45 | RC-64, RC-66, RC-60, RC-72, RC-68, RC-67, RC-61, RC-71 | Lámina del criterio: 4 categorías con su peso, regla de piso y bandas, con acme-demo.mx (28 por promedio y 60 por el piso). En el portal con Acme Demo, dicho como datos de demostración: score, banda, 4 barras y el panel '¿Por qué es crítico?' de un hallazgo, que en Acme explica por reglas. El detalle dice 'Antes decía 68': el 60 corrige el 68 que la semilla tenía escrito a mano. El score de un escaneo nuevo ya usa el clasificador alta, media o baja. Si la parte 3 terminó, el score de olmardo.com y sus 3 factores SHAP en frases | Lámina del criterio. Sin escaneo nuevo, olmardo.com trae su score del 29 oct, por reglas, y el SHAP se dice en voz alta |
| 6 | Portal: hallazgos, histórico y exportación | Israel | 1:15 | 9:00 | RC-17, RC-69, RC-71, RC-72, RC-57, RC-53 | Con Acme Demo: hallazgos de más a menos severo e histórico con el 68 escrito a mano y la corrección a 60, sin subida ni bajada y con el aviso de que no es cambio de exposición. 'Exportar CSV' y 'Exportar JSON' en hallazgos e histórico. 'Plan de acción': 'Actual 60' y, al resolver la brecha, 'Score estimado: 16 (−44)' | JSON de hallazgos de la API v1 (RC-53) y video de RC-84 si existe |
| 7 | Sesión sin encabezado | Germán | 0:45 | 9:45 | RC-58, RC-71 | Sale de Acme Demo y entra como Beta Corp: no ve nada de Acme. La barra lateral dice la empresa activa. La empresa sale de la sesión, no de un encabezado que alguien pueda cambiar | Captura de `test_api_v1` y `test_aislamiento` en verde |
| 8 | ¿Por qué LowTide? | Ernesto | 0:45 | 10:30 | RC-158 | Solo los 3 diferenciadores | Es lámina |
| 9 | Qué sigue | Ernesto | 0:30 | 11:00 | RC-156 | Lo que no se vio hoy y en qué sesión llega. Luego las preguntas al socio | Es lámina |

Los datos de olmardo.com (el certificado por vencer, el puerto 50000, el score del 29 oct) son los del 30 oct 2026. En otra fecha cambian: los esperados al día están en [`hallazgos_esperados.md`](hallazgos_esperados.md).

## Cómo se prueba sin red

La parte 3 es lo que corre `POST /api/v1/domains/{fqdn}/scans`. Sin red, `pruebas/test_orquestador.py` lo cubre así:

- `test_3c6_el_escaneo_normal_deja_ct_logs_y_dns_en_la_corrida`: las fuentes del escaneo normal (`fuentes_activas`) traen crt.sh (`ct_logs`) y DNS (`dns`), y un escaneo con las dos deja una corrida de cada una en `succeeded`, con crt.sh y el DNS simulados.
- `test_3c_un_escaneo_en_vivo_busca_dominios_parecidos_solo_en_crtsh`: crt.sh no sale del dominio autorizado y busca dominios parecidos solo en los registros de certificados.

La prueba de punta a punta con red de verdad es `test_7` de `pruebas/test_escaneos_api.py`. Solo corre con `EN_VIVO=1` y contra olmardo.com, con carta vigente y TXT verificado (`docs/politica_uso_etico.md`).
