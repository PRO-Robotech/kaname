// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_identity_seeded_only_by_baseline_injection_test.go — доказательство
// того, что гейт роста долга ПР-5/#2098 СПОСОБЕН упасть и способен смолчать.
//
// Порт с монорепо (снятый носитель инъекции того же семейства,
// `internal/repohygiene`, снят вынесением службы — `kacho#2597`). Дословно:
// предикат, фикстуры, три прогона. Изменилось только: пакет
// (`repohygiene_test` → `check_test`, экспортированные имена — `check.Xxx`).
//
// # ОДНО-ФАКТНОСТЬ: нарушение и законный близнец различаются ТОЛЬКО файлом
//
// Строка посева у обоих случаев побайтово одна и та же — тот же
// идентификатор, то же имя, то же назначение с признаком модульности.
// Различается ОДНО: какая миграция её завела.
//
// Прогонов поэтому ТРИ, а не два: контроль · нарушение · законный близнец.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const (
	// injectedBaseline — базовая миграция синтетического дерева: первая в
	// порядке применения.
	injectedBaseline = "0001_initial.sql"
	// injectedLater — миграция, приехавшая ПОСЛЕ применённой базовой.
	injectedLater = "0002_injected.sql"
)

// injectedModuleSARow — строка посева ровно той формы, которую читает разбор.
func injectedModuleSARow(id, name, description string) string {
	return "-- +goose Up\n" +
		"INSERT INTO kaname.service_accounts (id, account_id, name, description, created_at, " +
		"enabled, labels) VALUES ('" + id + "', 'acc1a18042d81fb438d6', '" + name + "', '" +
		description + "', now(), true, '{}');\n"
}

// injectedFold прогоняет синтетическое дерево через ТОТ ЖЕ разбор, что и гейт.
func injectedFold(t *testing.T, bodies map[string]string) (map[string]check.SeededServiceAccount, string) {
	t.Helper()
	ordered := []string{injectedBaseline}
	if _, ok := bodies[injectedLater]; ok {
		ordered = append(ordered, injectedLater)
	}
	alive, unknown, _ := check.FoldSeededServiceAccounts(ordered, bodies)
	if len(unknown) != 0 {
		t.Fatalf("инъекция НЕ ИСПОЛНЯЛАСЬ: разбор не узнал форму синтетической строки: %v", unknown)
	}
	return alive, check.BaselineMigrationOf(ordered)
}

const (
	injectedSAID   = "svaf5b9ff0a9d7e2c1b0"
	injectedSAName = "kacho-geo"
	injectedSADesc = "Module SA: kacho-geo (SEC-C least-priv)"
)

// TestSeedScopeGateIsSilentWhenTheBaselineSeedsTheIdentity — КОНТРОЛЬ и
// ЗАКОННЫЙ БЛИЗНЕЦ одновременно: та же строка, заведённая базовой миграцией.
func TestSeedScopeGateIsSilentWhenTheBaselineSeedsTheIdentity(t *testing.T) {
	t.Parallel()

	alive, baseline := injectedFold(t, map[string]string{
		injectedBaseline: injectedModuleSARow(injectedSAID, injectedSAName, injectedSADesc),
	})
	if len(alive) != 1 {
		t.Fatalf("контроль негоден: разобрано живых учёток %d вместо 1 — гейт молчит потому, "+
			"что ему нечего судить", len(alive))
	}
	if !alive[injectedSAID].IsModule() {
		t.Fatalf("контроль негоден: строка не опознана модульной — судья её не рассматривает " +
			"вовсе, и всякое его молчание ниже ничего не доказывает")
	}
	if got := check.ModuleIdentitiesSeededOutsideTheBaseline(alive, baseline); len(got) != 0 {
		t.Errorf("гейт краснеет на ИСПРАВНОМ: личность, посеянная базовой миграцией %s, дала "+
			"находок %d — такой гейт снимут первым же ложным срабатыванием:\n%v",
			baseline, len(got), got)
	}
	t.Logf("контроль: строка посеяна базовой %s · живых учёток %d · модульная да · находок 0",
		baseline, len(alive))
}

// TestSeedScopeGateRedWhenALaterMigrationSeedsTheIdentity — НАРУШЕНИЕ.
func TestSeedScopeGateRedWhenALaterMigrationSeedsTheIdentity(t *testing.T) {
	t.Parallel()

	alive, baseline := injectedFold(t, map[string]string{
		injectedBaseline: "-- +goose Up\n-- базовая без этой строки\n",
		injectedLater:    injectedModuleSARow(injectedSAID, injectedSAName, injectedSADesc),
	})

	got := check.ModuleIdentitiesSeededOutsideTheBaseline(alive, baseline)
	if len(got) != 1 {
		t.Fatalf("гейт НЕ СПОСОБЕН упасть: личность модуля %q, посеянная миграцией %s вне "+
			"базовой %s, дала находок %d вместо 1", injectedSAName, injectedLater, baseline, len(got))
	}
	for _, want := range []string{injectedLater, injectedSAName, injectedSAID} {
		if !strings.Contains(got[0], want) {
			t.Errorf("находка не называет координату %q — читатель пойдёт искать не там:\n%s",
				want, got[0])
		}
	}
	t.Logf("нарушение: находка названа с координатой — %s", got[0])
}

// TestSeedScopeGateRefusesAVerdictWithoutASubject — «не выполнилось» отличимо
// от зелёного по КАЖДОЙ из двух причин порознь.
func TestSeedScopeGateRefusesAVerdictWithoutASubject(t *testing.T) {
	t.Parallel()

	t.Run("обход пуст", func(t *testing.T) {
		t.Parallel()
		if why := check.SeedScopeUnfit(nil, map[string]check.SeededServiceAccount{}); why == "" {
			t.Error("пустой обход признан ЗЕЛЁНЫМ — «ноль находок» стало неотличимо от " +
				"«ноль прочитанного»")
		} else {
			t.Logf("обход пуст → предмета нет: %s", why)
		}
		if got := check.BaselineMigrationOf(nil); got != "" {
			t.Errorf("базовая выведена из пустого перечня как %q — судья сравнивал бы место "+
				"посева с именем, которого нет", got)
		}
	})

	t.Run("форма посева не узнана", func(t *testing.T) {
		t.Parallel()
		alive, _, _ := check.FoldSeededServiceAccounts(
			[]string{injectedBaseline},
			map[string]string{injectedBaseline: "-- +goose Up\n-- ни одной строки посева\n"})
		if why := check.SeedScopeUnfit([]string{injectedBaseline}, alive); why == "" {
			t.Error("миграция без единой узнанной строки посева признана годной — ослепший " +
				"разбор отчитался бы зелёным")
		} else {
			t.Logf("форма не узнана → предмета нет: %s", why)
		}
	})
}
