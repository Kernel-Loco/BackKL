-- =====================================================================
-- Cirdan · db/migraciones/013_pesos_por_organizacion.sql (#32)
-- Conserva el juego v1 como plantilla global y permite versiones de reglas
-- y pesos activas por organización. Cada tenant solo ve y modifica sus sets.
-- =====================================================================
BEGIN;

ALTER TABLE scoring_rule_sets
  ADD COLUMN organization_id uuid REFERENCES organizations(id);

ALTER TABLE scoring_rule_sets
  DROP CONSTRAINT scoring_rule_sets_version_key;

DROP INDEX scoring_rule_sets_one_active_uq;

CREATE UNIQUE INDEX scoring_rule_sets_global_version_uq
  ON scoring_rule_sets (version) WHERE organization_id IS NULL;
CREATE UNIQUE INDEX scoring_rule_sets_org_version_uq
  ON scoring_rule_sets (organization_id, version) WHERE organization_id IS NOT NULL;
CREATE UNIQUE INDEX scoring_rule_sets_global_active_uq
  ON scoring_rule_sets ((true)) WHERE organization_id IS NULL AND is_active;
CREATE UNIQUE INDEX scoring_rule_sets_org_active_uq
  ON scoring_rule_sets (organization_id) WHERE organization_id IS NOT NULL AND is_active;

ALTER TABLE scoring_rule_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scoring_rule_sets FORCE ROW LEVEL SECURITY;
CREATE POLICY scoring_rule_sets_tenant_isolation ON scoring_rule_sets
  USING (organization_id IS NULL OR organization_id = app_current_org())
  WITH CHECK (organization_id = app_current_org());

ALTER TABLE scoring_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE scoring_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY scoring_rules_tenant_isolation ON scoring_rules
  USING (EXISTS (
    SELECT 1 FROM scoring_rule_sets rs
    WHERE rs.id = rule_set_id
      AND (rs.organization_id IS NULL OR rs.organization_id = app_current_org())
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM scoring_rule_sets rs
    WHERE rs.id = rule_set_id AND rs.organization_id = app_current_org()
  ));

GRANT INSERT ON scoring_rule_sets TO cirdan_app;
GRANT UPDATE (is_active) ON scoring_rule_sets TO cirdan_app;
GRANT INSERT ON scoring_rules TO cirdan_app;

COMMENT ON COLUMN scoring_rule_sets.organization_id IS
  'NULL para el juego global de referencia; con valor, versión de pesos/reglas de una sola organización (#32).';

COMMIT;