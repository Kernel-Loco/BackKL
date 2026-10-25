# Códigos de las reglas del score (#30)

La lista de códigos que pide #30 (RC-66): una regla por cada tipo de hallazgo que emiten los recolectores #14 a #20, más las previstas de las extras #62 a #64. Son las 30 reglas del juego v1 (`90000000-0000-4000-8000-000000000001`). Las 01 a 07 están en `db/semillas/001_datos_demo.sql` y las 08 a 30 en `db/semillas/004_reglas_recolectores.sql`. Sus textos (título, qué significa y qué hacer) están en la tabla `scoring_rule_texts` de `db/migraciones/003_textos_reglas.sql`, y la API los devuelve con cada regla y cada explicación ([`contrato_api_v1.md`](contrato_api_v1.md)).

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
| 03 | `outdated_software` | infrastructure | high | 25.00 | #18 RC-46 y #17 RC-49 | Planeado |
| 04 | `exposed_rdp` | infrastructure | high | 25.00 | #17 RC-49 | Planeado |
| 05 | `dmarc_missing` | configuration | medium | 10.00 | #15 RC-48 | Planeado |
| 06 | `spf_missing` | configuration | low | 8.00 | #15 RC-48 | Planeado |
| 07 | `lookalike_domain` | digital_identity | medium | 15.00 | #14 RC-47 | Lo emite hoy |
| 08 | `cert_expiring_soon` | infrastructure | medium | 10.00 | #14 RC-47 y #14b RC-184 | Lo emite hoy |
| 09 | `domain_expiring_soon` | infrastructure | medium | 10.00 | #15b RC-166 | Planeado |
| 10 | `spf_allow_all` | configuration | medium | 10.00 | #15 RC-48 | Planeado |
| 11 | `dmarc_policy_none` | configuration | medium | 10.00 | #15 RC-48 | Planeado |
| 12 | `secret_in_public_repo` | data_leaks | critical | 40.00 | #16 RC-50 | Planeado |
| 13 | `email_in_public_commits` | digital_identity | low | 8.00 | #16 RC-50 | Planeado |
| 14 | `breach_exposure_old` | data_leaks | high | 25.00 | #19 RC-54 | Planeado |
| 15 | `breach_exposure_no_passwords` | data_leaks | medium | 10.00 | #19 RC-54 | Planeado |
| 16 | `personal_email_exposed` | digital_identity | medium | 15.00 | #20 RC-56 | Planeado |
| 17 | `email_pattern_exposed` | digital_identity | medium | 15.00 | #20 RC-56 | Planeado |
| 18 | `exposed_remote_admin` | infrastructure | high | 25.00 | #17 RC-49 | Planeado |
| 19 | `exposed_file_sharing` | infrastructure | high | 25.00 | #17 RC-49 | Planeado |
| 20 | `exposed_database` | infrastructure | high | 25.00 | #17 RC-49 | Planeado |
| 21 | `exposed_ot_device` | infrastructure | critical | 40.00 | #17 RC-49 | Planeado |
| 22 | `exposed_iot_device` | infrastructure | high | 25.00 | #17 RC-49 | Planeado |
| 23 | `exposed_service` | infrastructure | low | 8.00 | #17 RC-49 | Planeado |
| 24 | `known_vulnerability` | infrastructure | medium | 10.00 | #17 RC-49 y #18 RC-46 | Planeado |
| 25 | `server_version_disclosed` | configuration | low | 8.00 | #18 RC-46 | Planeado |
| 26 | `public_bucket` | data_leaks | high | 25.00 | #62 | Previsto |
| 27 | `subdomain_takeover_risk` | configuration | high | 25.00 | #62 | Previsto |
| 28 | `exposed_api_docs` | infrastructure | medium | 10.00 | #63 | Previsto |
| 29 | `api_auth_not_declared` | infrastructure | medium | 10.00 | #63 | Previsto |
| 30 | `secret_in_container_image` | data_leaks | critical | 40.00 | #64 | Previsto |

Por categoría: infrastructure 14, digital_identity 4, configuration 6 y data_leaks 6. Los secretos en repos públicos (#16) van a data_leaks y los correos en commits a digital_identity, como pide #30.

`spf_missing` también lo emite `cirdan/recolectores/ejemplo.py`, que es solo para pruebas y no cuenta como su recolector.

## Cobertura parcial

Si crt.sh no responde, la fuente `ct_logs` sigue con el respaldo de Cert Spotter (#14b), que no da certificados vencidos ni dominios parecidos. En esa corrida `cert_expired` y `lookalike_domain` quedan sin cobertura: van en `sin_cobertura` y no se muestran como 0 hallazgos (`SIN_COBERTURA` de `cirdan/recolectores/certspotter.py`). `lookalike_domain` además queda sin cobertura en todo escaneo, porque el orquestador nunca prende la búsqueda de dominios parecidos ([`contrato_plugin.md`](contrato_plugin.md)).

## Cómo agregar un código

1. Su texto en una migración nueva, `db/migraciones/NNN_descripcion.sql` con el siguiente número libre: título, qué significa y qué hacer. Va primero porque la FK de `scoring_rules.code` pide que el texto exista.
2. Su regla en una semilla nueva, `db/semillas/NNN_descripcion.sql`, con su categoría, severidad base, peso y tope. Nunca se editan la migración 001 ni la semilla 001. Desde #31 (RC-60) un cambio de reglas o de pesos crea un juego nuevo.
3. Su fila en esta tabla, y el código con su severidad en `CODIGOS` del recolector que lo emite.
4. `python -m unittest -v pruebas/test_catalogo_reglas.py` lo revisa. La prueba lee sola todas las migraciones y semillas de `db/` y compara el total con esta tabla. Cuando #31 cree el juego v2, que repite los mismos códigos, la prueba se filtra por juego: revisa que un código no se repita dentro de un mismo juego y compara esta tabla con las reglas del juego v1.

Los textos se escriben para alguien que no es de sistemas: el título es una frase corta sin punto final, y qué significa y qué hacer llevan una o dos frases cada uno, en imperativo con tú. Van sin siglas en mayúsculas, sin punto y coma, sin comillas y sin nombres de clientes. Los revisa alguien de otra área y los de OSINT, Ernesto.

## Cómo corregir un texto que ya se aplicó

Nunca se edita la migración 003. Una base que ya la tiene no la vuelve a aplicar con el texto nuevo, porque la 003 salta la tabla y los textos que ya existen, y solo una base nueva lo tomaría. El texto se corrige con una migración nueva, `db/migraciones/NNN_descripcion.sql` con el siguiente número libre, que hace `UPDATE scoring_rule_texts` del título, qué significa o qué hacer y llena `reviewed_by`, un `UPDATE` por código con `WHERE code = 'el_codigo'`. La prueba lee esos `UPDATE` en orden y revisa el texto que queda al final. En el mismo PR se actualizan `docs/api_v1/pesos.json` y `docs/api_v1/explicacion.json`, que `pruebas/test_api_v1.py` compara con la API.
