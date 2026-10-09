-- =====================================================================
-- Cirdan · 03_consultas.sql
-- Cuatro consultas que reproducen el portal de Figma. Corren como el rol
-- de la aplicación (cirdan_app) con el tenant de Acme Demo: ninguna filtra
-- por organización, el aislamiento lo pone Row-Level Security.
-- =====================================================================
\set QUIET on
SET TIME ZONE 'America/Mexico_City';
SET ROLE cirdan_app;
SET app.current_org = '20000000-0000-4000-8000-000000000001';   -- Acme Demo

\echo '== (a) Dashboard: dominios de Acme Demo =='
SELECT d.fqdn AS "Domain",
       CASE WHEN d.status = 'pending_verification' THEN 'Pending TXT'
            WHEN a.id IS NULL                      THEN 'Not authorized'
            WHEN a.revoked_at IS NOT NULL          THEN 'Revoked'
            WHEN current_date > a.valid_until      THEN 'Expired'
            ELSE 'Authorized' END                                     AS "Authorization",
       CASE WHEN t.result = 'match'                THEN 'Verified'
            WHEN d.status = 'pending_verification' THEN 'Pending'
            ELSE 'Not found' END                                      AS "TXT",
       coalesce(to_char(a.valid_until, 'DD Mon YYYY'), '—')           AS "Valid until",
       coalesce(s.score::text, '—')                                   AS "Score",
       CASE WHEN s.score IS NULL THEN '—'
            WHEN s.score >= 80 THEN 'Critical'
            WHEN s.score >= 60 THEN 'High'
            WHEN s.score >= 40 THEN 'Medium'
            ELSE 'Low' END                                            AS "Level",
       CASE WHEN d.status = 'pending_verification' THEN 'Not scanned'
            ELSE coalesce(to_char(d.last_scan_at, 'DD Mon YYYY, HH24:MI'), '—') END AS "Last scan"
  FROM domains d
  LEFT JOIN LATERAL (SELECT * FROM domain_authorizations x
                      WHERE x.domain_id = d.id ORDER BY x.valid_until DESC LIMIT 1) a ON true
  LEFT JOIN LATERAL (SELECT v.result FROM dns_txt_verifications v
                      WHERE v.domain_id = d.id ORDER BY v.checked_at DESC LIMIT 1) t ON true
  LEFT JOIN LATERAL (SELECT ds.score FROM domain_scores ds
                      WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1) s ON true
 ORDER BY s.score DESC NULLS LAST, d.status = 'pending_verification' DESC;

\echo '== (a) KPIs del dashboard =='
WITH dom AS (
  SELECT d.status,
         (SELECT max(x.valid_until) FROM domain_authorizations x
           WHERE x.domain_id = d.id AND x.revoked_at IS NULL)                    AS valid_until,
         (SELECT ds.score FROM domain_scores ds
           WHERE ds.domain_id = d.id ORDER BY ds.computed_at DESC LIMIT 1)       AS score
    FROM domains d)
SELECT count(*) FILTER (WHERE status = 'verified' AND valid_until >= current_date) AS "Monitored",
       count(*) FILTER (WHERE status = 'pending_verification')                    AS "Pending TXT",
       count(*) FILTER (WHERE valid_until < current_date)                          AS "Expired",
       round(avg(score))                                                           AS "Avg risk score",
       CASE WHEN round(avg(score)) >= 80 THEN 'Critical' WHEN round(avg(score)) >= 60 THEN 'High'
            WHEN round(avg(score)) >= 40 THEN 'Medium' ELSE 'Low' END              AS "Level",
       (SELECT count(*) FROM findings WHERE severity = 'critical' AND status = 'open') AS "Critical findings"
  FROM dom;

\echo '== (b) Most critical findings: acme-demo.mx =='
SELECT f.evidence->>'title'                                  AS "Finding",
       a.value                                               AS "Asset",
       initcap(replace(r.category, '_', ' '))                AS "Category",
       CASE s.code WHEN 'hibp' THEN 'HIBP API' WHEN 'shodan' THEN 'Shodan' WHEN 'dns' THEN 'DNS'
                   WHEN 'ct_logs' THEN 'CT' WHEN 'whois' THEN 'WHOIS' ELSE s.code END AS "Source",
       initcap(f.severity)                                   AS "Severity",
       CASE WHEN f.status <> 'open'           THEN initcap(f.status)
            WHEN f.detected_at >= sc.queued_at THEN 'New'
            ELSE 'Recurring' END                             AS "Status"
  FROM findings f
  JOIN domains d       ON d.id = f.domain_id
  JOIN assets a        ON a.id = f.asset_id
  JOIN scoring_rules r ON r.id = f.rule_id
  JOIN data_sources s  ON s.id = f.source_id
  LEFT JOIN scans sc   ON sc.id = f.last_scan_id
 WHERE d.fqdn = 'acme-demo.mx' AND f.status = 'open'
 ORDER BY array_position(ARRAY['critical','high','medium','low'], f.severity), f.detected_at DESC, f.id;

\echo '== (c) Risk by category: acme-demo.mx =='
WITH s AS (
  SELECT ds.score, ds.category_scores, rs.category_weights, rs.version
    FROM domain_scores ds
    JOIN domains d            ON d.id = ds.domain_id
    JOIN scoring_rule_sets rs ON rs.id = ds.rule_set_id
   WHERE d.fqdn = 'acme-demo.mx'
   ORDER BY ds.computed_at DESC LIMIT 1),
c AS (
  SELECT k.ord, k.label,
         (s.category_scores->>k.key)::int      AS score,
         (s.category_weights->>k.key)::numeric AS weight
    FROM s CROSS JOIN (VALUES (1, 'infrastructure',   'Infrastructure'),
                              (2, 'digital_identity', 'Digital Identity'),
                              (3, 'configuration',    'Configuration'),
                              (4, 'data_leaks',       'Data Leaks')) AS k(ord, key, label))
SELECT "Category", "Score", "Weight", "Score x weight" FROM (
  SELECT ord, label AS "Category", score AS "Score",
         to_char(weight * 100, 'FM990') || '%' AS "Weight", round(score * weight, 1) AS "Score x weight"
    FROM c
  UNION ALL
  SELECT 5, 'Global score (rule set v' || s.version || ')', s.score,
         to_char((SELECT sum(weight) FROM c) * 100, 'FM990') || '%',
         (SELECT round(sum(score * weight), 1) FROM c)
    FROM s) x
 ORDER BY ord;

\echo '== (d) Why this severity? 12 corporate emails found in public data breaches =='
SELECT initcap(sc.severity)                          AS "Severity",
       b.breach_name                                 AS "Breach (HIBP)",
       to_char(b.breach_date, 'DD Mon YYYY')         AS "Breach date",
       array_to_string(b.data_classes, ', ')         AS "Data classes (only categories)"
  FROM score_contributions sc
  JOIN findings f          ON f.id = sc.finding_id
  JOIN breach_exposures b  ON b.finding_id = f.id
 WHERE f.evidence->>'title' = '12 corporate emails found in public data breaches';

\echo '== (d) Rules that contributed most to the score =='
SELECT "Rule", "Points" FROM (
  SELECT 1 AS grp, r.points AS ord, r.label AS "Rule",
         CASE WHEN r.points > 0 THEN '+' || r.points ELSE r.points::text END AS "Points"
    FROM score_contributions sc
    JOIN findings f ON f.id = sc.finding_id
   CROSS JOIN LATERAL jsonb_to_recordset(sc.factors->'rules') AS r(label text, points int)
   WHERE f.evidence->>'title' = '12 corporate emails found in public data breaches'
  UNION ALL
  SELECT 2, 0, 'Total (score_contributions.penalty)', '+' || sc.penalty
    FROM score_contributions sc
    JOIN findings f ON f.id = sc.finding_id
   WHERE f.evidence->>'title' = '12 corporate emails found in public data breaches') x
 ORDER BY grp, ord DESC;

RESET ROLE;
