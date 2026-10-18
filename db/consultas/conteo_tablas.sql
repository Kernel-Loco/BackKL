-- =====================================================================
-- Cirdan · db/consultas/conteo_tablas.sql
-- Las 23 tablas por grupo del DBML, con filas y estado de RLS, y un
-- resumen de objetos. Corre como postgres (superusuario, ve todo).
-- =====================================================================
\echo '== Tablas de la base cirdan (filas reales, como postgres) =='
SELECT g.grupo AS "Grupo", c.relname AS "Tabla",
       (xpath('/row/n/text()',
              query_to_xml(format('SELECT count(*) AS n FROM public.%I', c.relname), false, true, '')))[1]::text::int AS "Filas",
       CASE WHEN c.relrowsecurity AND c.relforcerowsecurity THEN 'ENABLE+FORCE' ELSE '' END AS "RLS"
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  JOIN (VALUES ( 1, 'clientes_y_acceso',        'plans'),
               ( 2, 'clientes_y_acceso',        'organizations'),
               ( 3, 'clientes_y_acceso',        'users'),
               ( 4, 'clientes_y_acceso',        'api_keys'),
               ( 5, 'dominios_y_autorizacion',  'domains'),
               ( 6, 'dominios_y_autorizacion',  'domain_authorizations'),
               ( 7, 'dominios_y_autorizacion',  'dns_txt_verifications'),
               ( 8, 'escaneos_e_ingesta',       'data_sources'),
               ( 9, 'escaneos_e_ingesta',       'scans'),
               (10, 'escaneos_e_ingesta',       'scan_source_runs'),
               (11, 'activos_y_hallazgos',      'assets'),
               (12, 'activos_y_hallazgos',      'findings'),
               (13, 'activos_y_hallazgos',      'breach_exposures'),
               (14, 'inteligencia_y_score',     'cves'),
               (15, 'inteligencia_y_score',     'scoring_rule_sets'),
               (16, 'inteligencia_y_score',     'scoring_rules'),
               (17, 'inteligencia_y_score',     'domain_scores'),
               (18, 'inteligencia_y_score',     'score_contributions'),
               (19, 'entrega_e_integraciones',  'integrations'),
               (20, 'entrega_e_integraciones',  'alerts'),
               (21, 'entrega_e_integraciones',  'deliveries'),
               (22, 'entrega_e_integraciones',  'reports'),
               (23, 'auditoria',                'audit_log')) AS g(ord, grupo, tabla)
    ON g.tabla = c.relname
 WHERE c.relkind = 'r'
 ORDER BY g.ord;

\echo '== Resumen de objetos =='
SELECT (SELECT count(*) FROM pg_tables WHERE schemaname = 'public')                        AS tablas,
       (SELECT count(*) FROM pg_constraint
         WHERE contype = 'f' AND connamespace = 'public'::regnamespace)                     AS fk,
       (SELECT count(*) FROM pg_class
         WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'
           AND relrowsecurity AND relforcerowsecurity)                                      AS rls_force,
       (SELECT count(*) FROM pg_policies WHERE schemaname = 'public')                       AS politicas,
       (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
         WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace)              AS triggers,
       (SELECT count(*) FROM pg_indexes WHERE schemaname = 'public')                        AS indices;
