-- =====================================================================
-- Cirdan · db/semillas/004_reglas_recolectores.sql (RC-66, #30)
-- Reglas 08 a 30 del juego v1: las de los recolectores #14 a #20 y las
-- previstas de #62 a #64. Van en v1 y no en un juego v2 porque el motor de
-- score (#31, RC-60) todavía no calcula con ningún juego, y desde #31
-- cualquier cambio de reglas o pesos crea v2 (db/README.md, desviación 15).
-- No toca las 7 reglas de la semilla 001 ni category_weights.
-- weight 1.000 en todas: con la suma por categoría no cambia la nota.
-- max_penalty por severidad, por hallazgo: critical 40, high 25,
-- medium 10 (15 en digital_identity, como lookalike_domain) y low 8.
-- Sus textos ya están en scoring_rule_texts (migración 003).
-- =====================================================================
BEGIN;

INSERT INTO scoring_rules (id, rule_set_id, code, category, base_severity, weight, max_penalty) VALUES
 ('91000000-0000-4000-8000-000000000008','90000000-0000-4000-8000-000000000001','cert_expiring_soon',          'infrastructure',   'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000009','90000000-0000-4000-8000-000000000001','domain_expiring_soon',        'infrastructure',   'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000010','90000000-0000-4000-8000-000000000001','spf_allow_all',               'configuration',    'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000011','90000000-0000-4000-8000-000000000001','dmarc_policy_none',           'configuration',    'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000012','90000000-0000-4000-8000-000000000001','secret_in_public_repo',       'data_leaks',       'critical', 1.000, 40.00),
 ('91000000-0000-4000-8000-000000000013','90000000-0000-4000-8000-000000000001','email_in_public_commits',     'digital_identity', 'low',      1.000,  8.00),
 ('91000000-0000-4000-8000-000000000014','90000000-0000-4000-8000-000000000001','breach_exposure_old',         'data_leaks',       'high',     1.000, 25.00),
 ('91000000-0000-4000-8000-000000000015','90000000-0000-4000-8000-000000000001','breach_exposure_no_passwords','data_leaks',       'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000016','90000000-0000-4000-8000-000000000001','personal_email_exposed',      'digital_identity', 'medium',   1.000, 15.00),
 ('91000000-0000-4000-8000-000000000017','90000000-0000-4000-8000-000000000001','email_pattern_exposed',       'digital_identity', 'medium',   1.000, 15.00),
 ('91000000-0000-4000-8000-000000000018','90000000-0000-4000-8000-000000000001','exposed_remote_admin',        'infrastructure',   'high',     1.000, 25.00),
 ('91000000-0000-4000-8000-000000000019','90000000-0000-4000-8000-000000000001','exposed_file_sharing',        'infrastructure',   'high',     1.000, 25.00),
 ('91000000-0000-4000-8000-000000000020','90000000-0000-4000-8000-000000000001','exposed_database',            'infrastructure',   'high',     1.000, 25.00),
 ('91000000-0000-4000-8000-000000000021','90000000-0000-4000-8000-000000000001','exposed_ot_device',           'infrastructure',   'critical', 1.000, 40.00),
 ('91000000-0000-4000-8000-000000000022','90000000-0000-4000-8000-000000000001','exposed_iot_device',          'infrastructure',   'high',     1.000, 25.00),
 ('91000000-0000-4000-8000-000000000023','90000000-0000-4000-8000-000000000001','exposed_service',             'infrastructure',   'low',      1.000,  8.00),
 ('91000000-0000-4000-8000-000000000024','90000000-0000-4000-8000-000000000001','known_vulnerability',         'infrastructure',   'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000025','90000000-0000-4000-8000-000000000001','server_version_disclosed',    'configuration',    'low',      1.000,  8.00),
 ('91000000-0000-4000-8000-000000000026','90000000-0000-4000-8000-000000000001','public_bucket',               'data_leaks',       'high',     1.000, 25.00),
 ('91000000-0000-4000-8000-000000000027','90000000-0000-4000-8000-000000000001','subdomain_takeover_risk',     'configuration',    'high',     1.000, 25.00),
 ('91000000-0000-4000-8000-000000000028','90000000-0000-4000-8000-000000000001','exposed_api_docs',            'infrastructure',   'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000029','90000000-0000-4000-8000-000000000001','api_auth_not_declared',       'infrastructure',   'medium',   1.000, 10.00),
 ('91000000-0000-4000-8000-000000000030','90000000-0000-4000-8000-000000000001','secret_in_container_image',   'data_leaks',       'critical', 1.000, 40.00)
ON CONFLICT (rule_set_id, code) DO NOTHING;

COMMIT;
