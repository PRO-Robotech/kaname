// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package servicemanifest

// seed_form_test.go — форму раздела `seed` манифеста СЛУЖБЫ судит тот же судья,
// что у модулей (приёмка MRW-1, сценарии MRW-06…MRW-10).
//
// Дом каждого сценария — ДОКУМЕНТ В ПАМЯТИ: встроенный манифест, у которого один
// названный факт изменён разбором YAML, а не второй файл в дереве. Каждое
// отрицание стоит рядом со своим положительным близнецом — иначе оно зеленело
// бы на судье, отвергающем всё.
//
// MRW-09 и MRW-10 держит ОСНАСТКА ДЕРЕВА, а не старт службы (Р3): без внесённого
// канона судья «о существовании отношения не утверждает ничего», и оракул здесь —
// факт дома, взятый у той же оснастки (`manifestoracle.Canon`).

import (
	"errors"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifestoracle"
)

// seedDocument — встроенный манифест как дерево YAML, к которому проба
// применяет ОДНУ правку и отдаёт обратно байтами.
func seedDocument(t *testing.T, edit func(seed map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(Raw(), &doc); err != nil {
		t.Fatalf("встроенный манифест не разобран как YAML: %v", err)
	}
	seed, ok := doc["seed"].(map[string]any)
	if !ok {
		t.Fatalf("раздел `seed` у манифеста службы не объявлен — сценарии о его форме беспредметны (Р1)")
	}
	edit(seed)
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("документ пробы не собран: %v", err)
	}
	return out
}

func firstBinding(t *testing.T, seed map[string]any) map[string]any {
	t.Helper()
	bindings, ok := seed["accessBindings"].([]any)
	if !ok || len(bindings) == 0 {
		t.Fatal("манифест службы не объявляет ни одной выдачи — править нечего")
	}
	b, ok := bindings[0].(map[string]any)
	if !ok {
		t.Fatal("первая выдача не отображение")
	}
	return b
}

func canonOracle(t *testing.T) manifest.LoadOption {
	t.Helper()
	oracle, err := manifestoracle.Canon()
	if err != nil {
		t.Fatalf("канон модели прав не разобран: %v — проверка НЕ ИСПОЛНЯЛАСЬ", err)
	}
	return manifest.WithRelationOracle(oracle)
}

// TestMRW06_GroupWithoutAGrantIsRefusedByTheForm — группа без выдачи: находка
// `ErrGroupNeverGranted` с путём `seed.groups[0]` и номером строки.
func TestMRW06_GroupWithoutAGrantIsRefusedByTheForm(t *testing.T) {
	doc := seedDocument(t, func(seed map[string]any) { delete(seed, "accessBindings") })
	_, err := manifest.Load(doc)
	if !errors.Is(err, manifest.ErrGroupNeverGranted) {
		t.Fatalf("группа без выдачи принята судьёй формы: %v", err)
	}
	if want := "seed.groups[0]"; err == nil || !contains(err.Error(), want) {
		t.Fatalf("находка не называет путь %q: %v", want, err)
	}
	if !contains(err.Error(), "line ") && !contains(err.Error(), "строк") {
		t.Fatalf("находка не называет номер строки документа: %v", err)
	}
	t.Logf("находка: %v", err)
}

// TestMRW07_GroupWithItsGrantIsAccepted — положительный близнец MRW-06: тот же
// документ с выдачей, находок ноль.
func TestMRW07_GroupWithItsGrantIsAccepted(t *testing.T) {
	m, err := manifest.Load(seedDocument(t, func(map[string]any) {}))
	if err != nil {
		t.Fatalf("манифест службы отвергнут судьёй формы: %v", err)
	}
	if m.Seed == nil || len(m.Seed.Groups) != 1 || len(m.Seed.AccessBindings) != 1 {
		t.Fatalf("манифест службы объявляет не одну группу и не одну выдачу (Р1): %+v", m.Seed)
	}
	if len(m.Seed.ServiceAccounts) != 0 || len(m.Seed.Joins) != 0 {
		t.Fatalf("манифест службы объявляет личности либо вступления — своей служебной записи у службы не бывает (Р1)")
	}
	t.Logf("перепись связности: %s", m.Linkage())
}

// TestMRW08_AnchorOutsideTheClusterSingletonIsRefused — обе стороны оси якоря.
func TestMRW08_AnchorOutsideTheClusterSingletonIsRefused(t *testing.T) {
	t.Run("iam.account — находка ErrBindingAnchor", func(t *testing.T) {
		doc := seedDocument(t, func(seed map[string]any) { firstBinding(t, seed)["scopeType"] = "iam.account" })
		_, err := manifest.Load(doc)
		if !errors.Is(err, manifest.ErrBindingAnchor) {
			t.Fatalf("якорь вне кластерного singleton'а принят: %v", err)
		}
		if !contains(err.Error(), "seed.accessBindings[0]") {
			t.Fatalf("находка не называет путь seed.accessBindings[0]: %v", err)
		}
	})
	t.Run("iam.cluster — находок нет", func(t *testing.T) {
		doc := seedDocument(t, func(seed map[string]any) { firstBinding(t, seed)["scopeType"] = "iam.cluster" })
		if _, err := manifest.Load(doc); err != nil {
			t.Fatalf("якорь кластера отвергнут: %v", err)
		}
	})
}

// TestMRW09_RelationOutsideTheCanonIsRefusedByTheTreeJudge — с внесённым каноном
// отношение вне канона даёт `ErrRelationNotDeclared`; `fga_writer` принимается;
// без оракула (путь старта) тот же документ отказа НЕ производит.
func TestMRW09_RelationOutsideTheCanonIsRefusedByTheTreeJudge(t *testing.T) {
	outside := seedDocument(t, func(seed map[string]any) { firstBinding(t, seed)["grantedRelation"] = "no_such_relation" })

	t.Run("вне канона, с оракулом — находка", func(t *testing.T) {
		_, err := manifest.Load(outside, canonOracle(t))
		if !errors.Is(err, manifest.ErrRelationNotDeclared) {
			t.Fatalf("отношение вне канона принято: %v", err)
		}
	})
	t.Run("fga_writer, с оракулом — находок нет", func(t *testing.T) {
		if _, err := manifest.Load(seedDocument(t, func(map[string]any) {}), canonOracle(t)); err != nil {
			t.Fatalf("объявленное отношение отвергнуто: %v", err)
		}
	})
	t.Run("вне канона, без оракула — отказ не производится (путь старта)", func(t *testing.T) {
		if _, err := manifest.Load(outside); err != nil {
			t.Fatalf("без оракула судья утверждает о существовании отношения: %v", err)
		}
	})
}

// TestMRW10_RecipientKindTheRelationDoesNotAdmitIsRefused — группа на
// `system_viewer` (канон принимает `user` и `service_account`) отвергается с
// перечнем принимаемых видов; та же группа на `fga_writer` принимается.
func TestMRW10_RecipientKindTheRelationDoesNotAdmitIsRefused(t *testing.T) {
	viewer := seedDocument(t, func(seed map[string]any) { firstBinding(t, seed)["grantedRelation"] = "system_viewer" })

	t.Run("system_viewer, с оракулом — ErrRelationRecipientKind", func(t *testing.T) {
		_, err := manifest.Load(viewer, canonOracle(t))
		if !errors.Is(err, manifest.ErrRelationRecipientKind) {
			t.Fatalf("получатель, которого отношение не принимает, принят: %v", err)
		}
		if !contains(err.Error(), "service_account") {
			t.Fatalf("находка не называет принимаемые виды: %v", err)
		}
	})
	t.Run("fga_writer, с оракулом — принимается", func(t *testing.T) {
		if _, err := manifest.Load(seedDocument(t, func(map[string]any) {}), canonOracle(t)); err != nil {
			t.Fatalf("группа на fga_writer отвергнута: %v", err)
		}
	})
	t.Run("system_viewer, без оракула — отказ не производится (путь старта)", func(t *testing.T) {
		if _, err := manifest.Load(viewer); err != nil {
			t.Fatalf("без оракула судья утверждает о виде получателя: %v", err)
		}
	})
}

func contains(s, sub string) bool { return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0) }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
