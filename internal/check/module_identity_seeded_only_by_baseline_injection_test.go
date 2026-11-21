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

// Чтение SA другой записью не является посевом. Смена только цели превращает
// каждый lawful twin в неизвестную WRITE-форму, которая обязана краснеть.
func TestSeededServiceAccountsDMLTargetAndReadTwins(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, sql        string
		unknown, touched int
		deleted          bool
	}{
		{"actual_policy_epoch_seed", `INSERT INTO kaname.authority_policy_epoch(key)
 SELECT '*' UNION SELECT 'user:'||id FROM kaname.users UNION SELECT 'service_account:'||id FROM kaname.service_accounts
 UNION SELECT 'group:'||id FROM kaname.groups UNION SELECT 'role:'||id FROM kaname.roles
 UNION SELECT 'scope:'||id FROM kaname.accounts UNION SELECT 'carriers:role:'||id FROM kaname.roles
 UNION SELECT 'carrier_latch:role:'||id FROM kaname.roles`, 0, 0, false},
		{"insert_select_read", "INSERT INTO kaname.authority_policy_epoch(key) SELECT 'service_account:'||id FROM kaname.service_accounts", 0, 0, false},
		{"insert_select_write", "INSERT INTO kaname.service_accounts(id) SELECT id FROM kaname.authority_policy_epoch", 1, 1, false},
		{"update_from_read", "UPDATE kaname.authority_policy_epoch AS e SET key=s.id FROM kaname.service_accounts AS s", 0, 0, false},
		{"update_from_write", "UPDATE kaname.service_accounts AS s SET name=e.key FROM kaname.authority_policy_epoch AS e", 1, 1, false},
		{"delete_using_read", "DELETE FROM kaname.authority_policy_epoch AS e USING kaname.service_accounts AS s WHERE e.key=s.id", 0, 0, false},
		{"delete_using_write", "DELETE FROM kaname.service_accounts AS s USING kaname.authority_policy_epoch AS e WHERE e.key=s.id", 1, 1, false},
		{"unknown_update_write", "UPDATE kaname.service_accounts SET enabled=false", 1, 1, false},
		{"unknown_delete_write", "DELETE FROM kaname.service_accounts", 1, 1, false},
		{"known_delete_id", "DELETE FROM kaname.service_accounts WHERE id='" + injectedSAID + "'", 0, 1, true},
		{"known_delete_name", "DELETE FROM kaname.service_accounts WHERE name IN ('" + injectedSAName + "')", 0, 1, true},
		{"upper_unquoted_target", "UPDATE KANAME.SERVICE_ACCOUNTS SET enabled=false", 1, 1, false},
		{"quoted_insert_unknown", `INSERT INTO "kaname"."service_accounts"(id) VALUES ('x')`, 1, 1, false},
		{"quoted_delete_unknown", `DELETE FROM "kaname"."service_accounts" WHERE id='x'`, 1, 1, false},
		{"unicode_escaped_target", `UPDATE U&"kaname".U&"service\005faccounts" SET enabled=false`, 1, 1, false},
		{"quoted_target", `UPDATE "kaname"."service_accounts" SET enabled=false`, 1, 1, false},
		{"quoted_foreign_read", `UPDATE "kaname"."authority_policy_epoch" SET key=(SELECT id FROM "kaname"."service_accounts" LIMIT 1)`, 0, 0, false},
		{"quoted_upper_different_table", `UPDATE kaname."SERVICE_ACCOUNTS" SET name='kaname.service_accounts'`, 0, 0, false},
		{"foreign_schema", "UPDATE other.service_accounts SET name=(SELECT name FROM kaname.service_accounts LIMIT 1)", 0, 0, false},
		{"qualified_spaces", "UPDATE kaname . service_accounts SET enabled=false", 1, 1, false},
		{"unqualified_target_unknown", "UPDATE service_accounts SET enabled=false", 1, 1, false},
		{"only_target_unknown", "UPDATE ONLY kaname.service_accounts SET enabled=false", 1, 1, false},
		{"only_parenthesized_target", "DELETE FROM ONLY (kaname.service_accounts) WHERE id='x'", 1, 1, false},
		{"only_other_reads_sa", "UPDATE ONLY kaname.authority_policy_epoch SET key=(SELECT id FROM kaname.service_accounts LIMIT 1)", 0, 0, false},
		{"suffix_identifier", "UPDATE kaname.service_accounts_backup SET name='kaname.service_accounts'", 0, 0, false},
		{"dollar_identifier", "UPDATE kaname.service_accounts$backup SET name='kaname.service_accounts'", 0, 0, false},
		{"unicode_identifier_suffix", "UPDATE kaname.service_accountsя SET name='kaname.service_accounts'", 0, 0, false},
		{"dot_inside_quoted_identifier", `UPDATE "kaname.service_accounts" SET enabled=false`, 0, 0, false},
		{"literal_only", "INSERT INTO kaname.authority_policy_epoch(key) VALUES ('kaname.service_accounts')", 0, 0, false},
		{"select_only", "SELECT id FROM kaname.service_accounts", 0, 0, false},
		{"unknown_insert_prefix", "INSERT OR REPLACE INTO kaname.service_accounts(id) VALUES ('x')", 1, 1, false},
		{"unknown_three_part_target", "UPDATE db.kaname.service_accounts SET enabled=false", 1, 1, false},
		{"unknown_insert_target", "INSERT INTO (SELECT id FROM kaname.service_accounts) VALUES ('x')", 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bodies := map[string]string{
				injectedBaseline: injectedModuleSARow(injectedSAID, injectedSAName, injectedSADesc),
				injectedLater:    tc.sql + ";",
			}
			alive, unknown, touched := check.FoldSeededServiceAccounts([]string{injectedBaseline, injectedLater}, bodies)
			if len(unknown) != tc.unknown || touched != 1+tc.touched {
				t.Fatalf("unknown=%v touched=%d, нужно %d/%d", unknown, touched, tc.unknown, 1+tc.touched)
			}
			if len(unknown) != 0 && !strings.Contains(unknown[0], injectedLater) {
				t.Fatalf("находка не называет миграцию: %v", unknown)
			}
			_, present := alive[injectedSAID]
			if present == tc.deleted || len(alive) > 1 {
				t.Fatalf("посев изменён чтением/неизвестной формой: deleted=%v alive=%+v", tc.deleted, alive)
			}
			if present && (alive[injectedSAID].Where != injectedBaseline || !alive[injectedSAID].IsModule()) {
				t.Fatalf("утрачены происхождение или Module SA: %+v", alive[injectedSAID])
			}
		})
	}
}
