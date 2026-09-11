// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_scope_chain_stays_empty_injection_test.go — ДОКАЗАТЕЛЬСТВО того, что
// гейт §2.8 способен упасть и способен смолчать.
//
// Порт одноимённой пробы репозитория платформы, снят там вынесением службы —
// `kacho#2597`. Дословно: все четыре прогона.
// Изменилось только: пакет (`repohygiene` → `check_test`, экспортированные
// имена — `check.Xxx`).
//
// Инъекция подаётся НАСТОЯЩИМ входом — текстом ветви той же формы, какую
// пишет производитель. Осей три, и каждая прогоняется отдельно:
//
//	контроль          законные ветви (5a) и (5b) — гейт МОЛЧИТ;
//	инъекция нового   третья ветвь без ярусного источника — гейт КРАСНЕЕТ;
//	инъекция прямого  посев звена значениями — краснеет тоже, у него
//	                  предиката нет вовсе.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// roleScopeChainLegalBranches — ДВЕ законные ветви, дословно по форме
// производителя. Положительный контроль.
const roleScopeChainLegalBranches = `
INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
  SELECT 'iam_role'::text, o.id, 'account'::text, o.account_id, 1
    FROM kaname.roles o
   WHERE COALESCE(o.account_id, '') <> ''
UNION ALL
  SELECT 'iam_role'::text, o.id, 'project'::text, o.project_id, 1
    FROM kaname.roles o
   WHERE COALESCE(o.project_id, '') <> '';
`

// TestRoleScopeChainGateStaysSilentOnTheLegalTwin — КОНТРОЛЬ.
func TestRoleScopeChainGateStaysSilentOnTheLegalTwin(t *testing.T) {
	t.Parallel()
	found, census := check.ScanRoleScopeChain("internal/migrations/legal.sql",
		roleScopeChainLegalBranches)

	t.Logf("перепись контроля: ветвей %d, из них ярусных %d, находок %d",
		census.Branches, census.TierSourced, len(found))

	if census.Branches != 2 {
		t.Fatalf("законных ветвей распознано %d вместо двух: распознаватель не видит "+
			"формы, которую пишет производитель, и его молчание ниже ничего не значит",
			census.Branches)
	}
	if census.TierSourced != 2 {
		t.Fatalf("ярусными признаны %d ветви из двух: гейт краснел бы на законном "+
			"производителе и был бы снят первым же читателем", census.TierSourced)
	}
	if len(found) != 0 {
		t.Fatalf("гейт нашёл %d находок на ЗАКОННЫХ ветвях: %v", len(found), found)
	}
}

// TestRoleScopeChainGateRedsOnAThirdProducer — ИНЪЕКЦИЯ НОВОГО.
func TestRoleScopeChainGateRedsOnAThirdProducer(t *testing.T) {
	t.Parallel()
	injected := roleScopeChainLegalBranches + `
UNION ALL
  SELECT 'iam_role'::text, o.id, 'cluster'::text, o.cluster_id, 1
    FROM kaname.roles o
   WHERE COALESCE(o.cluster_id, '') <> '';
`
	found, census := check.ScanRoleScopeChain("internal/migrations/injected.sql", injected)

	t.Logf("перепись инъекции: ветвей %d, из них ярусных %d, находок %d",
		census.Branches, census.TierSourced, len(found))

	if len(found) != 1 {
		t.Fatalf("третья ветвь без ярусного источника дала %d находок вместо одной: "+
			"гейт не способен упасть на предмете, ради которого заведён", len(found))
	}
	if census.TierSourced != 2 {
		t.Errorf("законных ветвей признано ярусными %d вместо двух: инъекция уронила "+
			"НЕ ТОЛЬКО проверяемое, и красное могло прийти от соседа", census.TierSourced)
	}
	if !strings.Contains(found[0].What, "cluster") {
		t.Errorf("находка не называет виновную ветвь: %q — читатель пойдёт искать её "+
			"перебором", found[0].What)
	}
	if found[0].Line == 0 {
		t.Error("находка без номера строки: координата обязана быть точной")
	}
}

// TestRoleScopeChainGateRedsOnADirectSeed — ИНЪЕКЦИЯ ПРЯМОГО ПОСЕВА.
func TestRoleScopeChainGateRedsOnADirectSeed(t *testing.T) {
	t.Parallel()
	injected := `
INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
VALUES ('iam_role', 'rol_probe', 'account', 'acc_probe', 1);
`
	found, census := check.ScanRoleScopeChain("internal/migrations/seed.sql", injected)

	t.Logf("перепись посева: ветвей %d, находок %d", census.Branches, len(found))
	if len(found) != 1 {
		t.Fatalf("прямой посев звена дал %d находок вместо одной: у него нет предиката "+
			"вовсе, и признать его законным нечем", len(found))
	}
}

// TestRoleScopeChainGateIgnoresANonProducer — ВТОРОЙ законный близнец.
func TestRoleScopeChainGateIgnoresANonProducer(t *testing.T) {
	t.Parallel()
	dictionary := `
INSERT INTO kaname.scope_chain_type_dictionary (dotted, model_type) VALUES
  ('iam.role', 'iam_role');
`
	found, census := check.ScanRoleScopeChain("internal/migrations/dict.sql", dictionary)
	t.Logf("перепись словаря: упоминаний таблицы звеньев %d, ветвей %d, находок %d",
		census.Statements, census.Branches, len(found))
	if len(found) != 0 {
		t.Fatalf("гейт нашёл %d находок в СЛОВАРЕ типов: он судит по имени типа, а не по "+
			"производству звена, и будет снят первым же читателем", len(found))
	}
}
