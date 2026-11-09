# Códigos de las reglas del score (#30)

La lista de códigos que pide #30 (RC-66): una regla por cada tipo de hallazgo que emiten los recolectores #14 a #20, más las previstas de las extras #62 a #64. Son las 30 reglas del juego v1 (`90000000-0000-4000-8000-000000000001`). Las 01 a 07 están en `db/semillas/001_datos_demo.sql` y las 08 a 30 en `db/semillas/004_reglas_recolectores.sql`. Sus textos (título, qué significa y qué hacer) están en la tabla `scoring_rule_texts`: los pone `db/migraciones/003_textos_reglas.sql` y los corrige `db/migraciones/005_textos_revisados.sql`, y la API los devuelve con cada regla y cada explicación ([`contrato_api_v1.md`](contrato_api_v1.md)).

`pruebas/test_catalogo_reglas.py` revisa sin base ni red que esta tabla, las semillas, los textos y los recolectores digan lo mismo. Falla si un recolector declara en `CODIGOS` un código sin regla o con otra severidad. Cada recolector debe emitir solo los códigos de su `CODIGOS`, con esa severidad. La prueba revisa lo que emite de verdad solo en `ejemplo`.

## Cómo leer la tabla

- **Id:** los dos últimos dígitos del id de la regla, `91000000-0000-4000-8000-0000000000NN`.
- **Severidad base:** la de la regla, y con la que el recolector emite el hallazgo. El motor de score (#31) la puede subir ([`criterio_criticidad.md`](criterio_criticidad.md)).
- **Tope:** `max_penalty`, lo más que un hallazgo suma a la nota de su categoría (más alto es más riesgo). En las 23 reglas nuevas va por severidad: critical 40, high 25, medium 10 (15 en digital_identity, como `lookalike_domain`) y low 8. Las 7 de la semilla 001 no cambiaron, por eso `cert_expired` conserva 20.
- **Peso:** `weight`, que no tiene columna en la tabla. Las 23 reglas nuevas llevan 1.000 y las 7 de la semilla 001 conservan el suyo: 1.000 en `breach_exposure` y `lookalike_domain`, 0.400 en `cert_expired` y `outdated_software`, 0.200 en `exposed_rdp` y 0.500 en `dmarc_missing` y `spf_missing` (`db/semillas/001_datos_demo.sql:36-42` y `docs/api_v1/pesos.json`). Con la suma por categoría el peso no cambia la nota (`db/cirdan_esquema.dbml`).
- **Recolector:** el número del backlog y la clave de Jira de la tarjeta que emite el código.
- **Estado:** Lo emite hoy (su recolector está en dev), Planeado (su recolector es una tarjeta de #14 a #20 que todavía no está en dev) o Previsto (sale de las extras #62 a #64).

## Las 30 reglas

| Id | Código | Categoría | Severidad base | Tope | Recolector | Estado |
|---|---|---|---|---|---|---|
| 01 | `breach_exposure` | data_leaks | critical | 40.00 | #19 RC-54 | Planeado |
| 02 | `cert_expired` | infrastructure | high | 20.00 | #14 RC-47 | Lo emite hoy |
| 03 | `outdated_software` | infrastructure | high | 25.00 | #18 RC-46 y #17 RC-49 | Lo emite hoy |
| 04 | `exposed_rdp` | infrastructure | high | 25.00 | #17 RC-49 | Lo emite hoy |
| 05 | `dmarc_missing` | configuration | medium | 10.00 | #15 RC-48 | Lo emite hoy |
| 06 | `spf_missing` | configuration | low | 8.00 | #15 RC-48 | Lo emite hoy |
| 07 | `lookalike_domain` | digital_identity | medium | 15.00 | #14 RC-47 | Lo emite hoy |
| 08 | `cert_expiring_soon` | infrastructure | medium | 10.00 | #14 RC-47 y #14b RC-184 | Lo emite hoy |
| 09 | `domain_expiring_soon` | infrastructure | medium | 10.00 | #15b RC-166 | Lo emite hoy |
| 10 | `spf_allow_all` | configuration | medium | 10.00 | #15 RC-48 | Lo emite hoy |
| 11 | `dmarc_policy_none` | configuration | medium | 10.00 | #15 RC-48 | Lo emite hoy |
| 12 | `secret_in_public_repo` | data_leaks | critical | 40.00 | #16 RC-50 | Lo emite hoy |
| 13 | `email_in_public_commits` | digital_identity | low | 8.00 | #16 RC-50 | Lo emite hoy |
| 14 | `breach_exposure_old` | data_leaks | high | 25.00 | #19 RC-54 | Planeado |
| 15 | `breach_exposure_no_passwords` | data_leaks | medium | 10.00 | #19 RC-54 | Planeado |
| 16 | `personal_email_exposed` | digital_identity | medium | 15.00 | #20 RC-56 | Planeado |
| 17 | `email_pattern_exposed` | digital_identity | medium | 15.00 | #20 RC-56 | Planeado |
| 18 | `exposed_remote_admin` | infrastructure | high | 25.00 | #17 RC-49 | Lo emite hoy |
| 19 | `exposed_file_sharing` | infrastructure | high | 25.00 | #17 RC-49 | Lo emite hoy |
| 20 | `exposed_database` | infrastructure | high | 25.00 | #17 RC-49 | Lo emite hoy |
| 21 | `exposed_ot_device` | infrastructure | critical | 40.00 | #17 RC-49 | Planeado |
| 22 | `exposed_iot_device` | infrastructure | high | 25.00 | #17 RC-49 | Planeado |
| 23 | `exposed_service` | infrastructure | low | 8.00 | #17 RC-49 | Lo emite hoy |
| 24 | `known_vulnerability` | infrastructure | medium | 10.00 | #17 RC-49 y #18 RC-46 | Lo emite hoy |
| 25 | `server_version_disclosed` | configuration | low | 8.00 | #18 RC-46 | Planeado |
| 26 | `public_bucket` | data_leaks | high | 25.00 | #62 | Previsto |
| 27 | `subdomain_takeover_risk` | configuration | high | 25.00 | #62 | Previsto |
| 28 | `exposed_api_docs` | infrastructure | medium | 10.00 | #63 | Previsto |
| 29 | `api_auth_not_declared` | infrastructure | medium | 10.00 | #63 | Previsto |
| 30 | `secret_in_container_image` | data_leaks | critical | 40.00 | #64 | Previsto |

Por categoría: infrastructure 14, digital_identity 4, configuration 6 y data_leaks 6. Los secretos en repos públicos (#16) van a data_leaks y los correos en commits a digital_identity, como pide #30.

`spf_missing` también lo emite `cirdan/recolectores/ejemplo.py`, que es solo para pruebas y no cuenta como su recolector.

## Cobertura parcial

Si crt.sh no responde, la fuente `ct_logs` sigue con el respaldo de Cert Spotter (#14b), que no da certificados vencidos ni dominios parecidos. En esa corrida `cert_expired` y `lookalike_domain` quedan sin cobertura: van en `sin_cobertura` y no se muestran como 0 hallazgos (`SIN_COBERTURA` de `cirdan/recolectores/certspotter.py`). Si crt.sh responde, Cert Spotter suma los certificados vigentes que crt.sh no trae y la cobertura no cambia. Pero si pueden faltar certificados (crt.sh solo respondió a la búsqueda por nombre, o Cert Spotter no respondió o no dio todas sus páginas), `ct_logs` da `revisados` con `nombre@vencimiento` de los certificados que llegaron y va en `stats.sources_partial` (RC-55). `lookalike_domain` además queda sin cobertura en todo escaneo, porque el orquestador nunca prende la búsqueda de dominios parecidos ([`contrato_plugin.md`](contrato_plugin.md)).

La fuente `shodan` (#17) usa Shodan InternetDB, que no pide llave. Sin la llave de Shodan (#8, RC-40) no hay API de host: `exposed_iot_device`, `exposed_ot_device` y `outdated_software` van en `sin_cobertura` de `shodan` en todo escaneo (`SIN_LLAVE` de `cirdan/recolectores/shodan.py`). Los dos primeros siguen como Planeado y `outdated_software` lo emite la visita web. Si una corrida no revisa todas las IP del dominio (Cert Spotter caído, un 429, los topes de nombres o de IP, una respuesta de InternetDB que no se puede leer o el tope de tiempo), los códigos de `CODIGOS` sin hallazgos también van ahí, y lo que sí se revisó completo va en `revisados` (la IP para sus puertos e `IP/cve` para sus CVE) y, si se conocen todas las IP, lo demás de esas IP en `sin_revisar`: un hallazgo de una IP que no se revisó no se cierra aunque su código traiga otros (#23). Las CVE que pasan del tope de 25 por IP van en `omitidos` y tampoco se cierran.

La fuente `web` (#18, RC-46) es la visita web de la actividad 6 del Anexo A (`cirdan/recolectores/visita.py`): pide la página principal de cada sitio del dominio por https y saca sus tecnologías, `outdated_software` con endoflife.date y `known_vulnerability` con la NVD. Sus partes son los sitios: un sitio con reto o bloqueo del WAF, que no se pudo visitar o al que le faltó la respuesta de endoflife.date o de la NVD queda en `sin_revisar`, y si ningún sitio quedó revisado los dos códigos van en `sin_cobertura`. Las CVE que pasan del tope de 25 por tecnología van en `omitidos`.

## Cómo agregar un código

1. Su texto en una migración nueva, `db/migraciones/NNN_descripcion.sql` con el siguiente número libre: título, qué significa y qué hacer. Va primero porque la FK de `scoring_rules.code` pide que el texto exista. Si lo emite un recolector de #14 a #20, la misma migración lo firma después del INSERT con `UPDATE scoring_rule_texts SET reviewed_by = 'ErnestoDL', updated_at = now() WHERE code = 'el_codigo';`, y en las pruebas se sube el 25 de `test_10` de `pruebas/test_catalogo_reglas.py` y el de la prueba 15 de `pruebas/test_aislamiento.py`. En la misma migración y en la misma transacción, después del INSERT del texto, va su mapeo a marcos en `scoring_rule_framework_mappings` (ATT&CK, ISO 27001 y CIS, con las versiones que espera la prueba 15: hoy Enterprise v19, ISO/IEC 27001:2022 y CIS Controls v8.1). La técnica de ATT&CK va solo si su descripción en esa versión nombra lo que detecta la regla como algo que un adversario busca, adquiere o usa. Si no, va sin técnica y con la razón. El enlace va fijo a la versión, como `https://attack.mitre.org/versions/v19/techniques/T1589/001/`, o a `/versions/v19/techniques/enterprise/` sin técnica, y la prueba 15 lo revisa. Los nombres son breves y en español, sin copiar la descripción ni el texto de ISO, CIS ni MITRE. La FK diferida de la 012 revisa en el COMMIT que todo texto tenga su mapeo y, si falta, la migración entera se deshace.
2. Su regla en una semilla nueva, `db/semillas/NNN_descripcion.sql`, con su categoría, severidad base, peso y tope. Nunca se editan la migración 001 ni la semilla 001. Desde #31 (RC-60) un cambio de reglas o de pesos crea un juego nuevo.
3. Su fila en esta tabla, y el código con su severidad en `CODIGOS` del recolector que lo emite.
4. `python -m unittest -v pruebas/test_catalogo_reglas.py` lo revisa. La prueba lee sola todas las migraciones y semillas de `db/`, compara el total con esta tabla y revisa que los textos y los mapeos a marcos tengan los mismos códigos, sin repetidos (prueba 4b). No revisa las versiones de los marcos ni lee el orden ni las transacciones del SQL: lo que de verdad queda en la base lo revisan la FK diferida de la 012 al cargarla y la prueba 15 de `pruebas/test_aislamiento.py`, que pide 30 textos y 30 mapeos y la versión que espera de cada marco, con sus enlaces. Con una regla nueva se sube ese 30. Por eso la prueba 4b también falla si una migración o una semilla que nombra las reglas, los textos o el mapeo, o que arma SQL que no se ve, es nueva o cambió y no tiene su huella en `HUELLAS_DB`: el CI carga la base desde cero y corre la prueba 15 antes que ella, y si pasa se pone la huella que da el mensaje ([`db/README.md`](../db/README.md#huellas-de-db)). Un cambio de versión de ATT&CK (por ejemplo, de Enterprise v19 a v20) va en una migración nueva con UPDATE de los mapeos, que también cambia los enlaces a la versión nueva (`/versions/v20/`), y en el mismo cambio se pone la versión nueva en el trío que espera la prueba 15, en `pruebas/test_api_v1.py`, en las notas de `attack_version` y `attack_source_url` de `db/cirdan_esquema.dbml`, en la entrada de MITRE ATT&CK de `NOTICE`, en su fila de `docs/servicios_externos.md` y en la fila de la 011 de `db/README.md`, y la huella de la migración nueva. Una edición nueva de ISO 27001 o de CIS Controls no sigue esta receta: es un cambio del contrato de la API v1, porque las llaves `iso_27001_2022` y `cis_controls_v8_1` de `cirdan/api/v1.py` llevan la edición y los CHECK de la 011 sobre `iso_control_id` y `cis_safeguard_id` siguen esas ediciones. Cuando #31 cree el juego v2, que repite los mismos códigos, la prueba se filtra por juego: revisa que un código no se repita dentro de un mismo juego y compara esta tabla con las reglas del juego v1.

Los textos se escriben para alguien que no es de sistemas: el título es una frase corta sin punto final, y qué significa y qué hacer llevan una o dos frases cada uno, en imperativo con tú. Van sin siglas en mayúsculas, sin punto y coma, sin comillas y sin nombres de clientes. Los de OSINT los revisa Ernesto y el resto alguien de otra área o Ernesto, que firmó los de #62 a #64 en la 006.

## Cómo corregir un texto que ya se aplicó

Nunca se edita la migración 003. Una base que ya la tiene no la vuelve a aplicar con el texto nuevo, porque la 003 salta la tabla y los textos que ya existen, y solo una base nueva lo tomaría. El texto se corrige con una migración nueva, `db/migraciones/NNN_descripcion.sql` con el siguiente número libre, que hace `UPDATE scoring_rule_texts` del título, qué significa o qué hacer, un `UPDATE` por código con `WHERE code = 'el_codigo'`. El mismo `UPDATE` dice en `reviewed_by` quién revisó el texto nuevo: Ernesto en los de OSINT y alguien de otra área o Ernesto en el resto. Si nadie lo ha revisado todavía, lleva `reviewed_by = NULL`, como los de #62 a #64 en la 005 antes de que los firmara la 006, porque sin `reviewed_by` la fila conservaría la firma del texto anterior. La prueba lee esos `UPDATE` en orden y revisa el texto que queda al final y que las reglas OSINT las haya firmado ErnestoDL. En el mismo PR se actualizan `docs/api_v1/pesos.json` y `docs/api_v1/explicacion.json`, que `pruebas/test_api_v1.py` compara con la API.
