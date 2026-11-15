-- Una línea por tabla: esquema.tabla|filas|RLS|FORCE|políticas (#115, RC-233).
-- Se corre como postgres (superusuario: ve todas las filas aunque la tabla tenga FORCE RLS) en la base original
-- y en la restaurada, y las dos salidas tienen que ser iguales. Solo lee.
SELECT format('%s.%s|%s|%s|%s|%s',
              n.nspname, c.relname,
              (xpath('/row/c/text()',
                     query_to_xml(format('SELECT count(*) AS c FROM %I.%I', n.nspname, c.relname), false, true, '')))[1]::text,
              c.relrowsecurity, c.relforcerowsecurity,
              (SELECT count(*) FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname))
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_toast%'
ORDER BY 1;
