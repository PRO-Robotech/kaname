// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// emptyclass_test.go — MOD-RL-05 и его парный положительный.
//
// Приёмка: services/iam/docs/engineering/acceptance/module-manifest-roles-and-seed-grants.md
// §3.6 п. 3, §3.7, §4.1 (MOD-RL-05), §10 п. 7 (числа находок по проверкам).
//
// # Вход — НАСТОЯЩИЙ, и он несёт дефект сам
//
// Фикстура манифеста лежит у соседнего пакета (`../testdata/`), и читается она
// оттуда намеренно: своя копия была бы вторым манифестом об одном предмете и
// разошлась бы с первым молча. Каталог прав берётся встроенный — тот самый, что
// читает посев.
//
// Роль `vpc.addressPoolAdmin` фикстуры называет ресурс `addressPool` и пять
// классов; каждое из 22 действий этого ресурса гейтится `system_admin` на
// `cluster`, то есть парой, которую правило роли модуля не пишет ни при каком
// написании. Пять пустых классов — не выдумка пробы, а свойство дерева.
//
// Роль `vpc.internalConsumer` той же фикстуры — законный близнец: её классы
// `get` и `list` на `address`, `networkInterface` и `subnet` покрывают
// действия, гейтящиеся `v_get` / `v_list` на объекте типа ресурса.
package roleexport_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// mustCatalog — встроенный каталог прав, приведённый к порту пакета.
//
// Читается ТЕМ ЖЕ загрузчиком, что и у посева: второй разборщик той же строки
// разошёлся бы с первым молча, и разошёлся бы там, где расхождение не видно.
func mustCatalog(t *testing.T) []roleexport.CatalogEntry {
	t.Helper()
	reg, err := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("каталог прав не прочитан: %v", err)
	}
	rows := reg.All()
	if len(rows) == 0 {
		t.Fatal("каталог прочитан пустым: «ноль находок» стало бы неотличимо от «ноль прочитанного»")
	}
	out := make([]roleexport.CatalogEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, roleexport.CatalogEntry{
			FQN:              r.FQN,
			RequiredRelation: r.RequiredRelation,
			ScopeObjectType:  r.ScopeExtractor.ObjectType,
		})
	}
	return out
}

// fixturePath — координата фикстуры, названная ОДИН раз на пакет.
//
// Второе её объявление разошлось бы с первым молча ровно тогда, когда фикстуру
// переносят: обе копии читаются, и неверная отвечает «файла нет» из другой пробы.
const fixturePath = "../testdata/vpc.resources-fixture.yaml"

// mustFixture — манифест vpc со всеми четырьмя разделами.
func mustFixture(t *testing.T) *manifest.Manifest {
	t.Helper()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("чтение фикстуры соседнего пакета: %v", err)
	}
	m, err := manifest.Load(data)
	if err != nil {
		t.Fatalf("фикстура отвергнута загрузчиком: %v", err)
	}
	return m
}

// mustActions — привязка записей каталога к действиям модулей.
func mustActions(t *testing.T) []roleexport.Action {
	t.Helper()
	actions, faults := roleexport.Attribute(mustCatalog(t))
	for _, f := range faults {
		t.Logf("вне привязки: %v", f)
	}
	if len(actions) == 0 {
		t.Fatal("привязано ноль действий: судить нечем")
	}
	return actions
}

// ── MOD-RL-05 ───────────────────────────────────────────────────────────────

// TestMODRL05EmptyClassOnANamedResourceIsRefused — отрицательный.
//
// Единица — ПАРА (ресурс, класс) у роли, и она названа здесь же: сложение
// находок разных проверок дало бы величину, которую нечем перемерить.
func TestMODRL05EmptyClassOnANamedResourceIsRefused(t *testing.T) {
	m := mustFixture(t)
	faults, census := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))

	t.Logf("перепись: %s", census.Summary())

	var empty []roleexport.Finding
	for _, f := range faults {
		var got roleexport.Finding
		if errors.As(f, &got) && errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) {
			empty = append(empty, got)
		}
	}
	if len(empty) != 5 {
		t.Fatalf("пустых классов найдено %d, в фикстуре их пять "+
			"(get · list · create · update · delete у vpc.addressPoolAdmin); находки: %v",
			len(empty), faults)
	}
	seen := map[string]bool{}
	for _, f := range empty {
		if f.Role != "vpc.addressPoolAdmin" {
			t.Errorf("пустой класс приписан роли %q; в фикстуре пуста только vpc.addressPoolAdmin", f.Role)
		}
		if f.Resource != "addressPool" {
			t.Errorf("пустой класс приписан ресурсу %q, ожидался addressPool", f.Resource)
		}
		seen[f.Class] = true
	}
	for _, class := range []string{"get", "list", "create", "update", "delete"} {
		if !seen[class] {
			t.Errorf("класс %q не назван находкой, хотя пуст", class)
		}
	}
}

// TestMODRL05RefusalNamesThePairAndTheWayOut — отказ обязан нести ТРИ вещи.
//
// Без причины автор прочтёт отказ как «в манифесте опечатка» и пойдёт искать её
// у себя; без пригодных классов — не узнает, что писать; без пары «отношение +
// объект» отказ по `viewer@project` будет неотличим от отказа по
// `viewer@vpc_network`, а чинятся они разным.
func TestMODRL05RefusalNamesThePairAndTheWayOut(t *testing.T) {
	m := mustFixture(t)
	faults, _ := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))

	var refusal string
	for _, f := range faults {
		if errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) {
			refusal = f.Error()
			break
		}
	}
	if refusal == "" {
		t.Fatal("ни одного отказа о пустом классе: проверять нечего")
	}
	for _, want := range []string{
		"system_admin", // отношение, которое спрашивает гейт
		"cluster",      // объект, НА КОТОРОМ оно спрашивается
		"vpc.addressPoolAdmin",
		"addressPool",
	} {
		if !strings.Contains(refusal, want) {
			t.Errorf("отказ не называет %q; отказ: %s", want, refusal)
		}
	}
}

// ── MOD-RL-05, парный положительный ─────────────────────────────────────────

// TestMODRL05aNonEmptyClassIsSilent — законный близнец.
//
// Без него проверка зеленела бы на реализации, роняющей ВСЯКИЙ класс: отказ,
// отвергающий любой вход, отказом не является.
func TestMODRL05aNonEmptyClassIsSilent(t *testing.T) {
	m := mustFixture(t)
	faults, _ := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))

	for _, f := range faults {
		var got roleexport.Finding
		if errors.As(f, &got) && got.Role == "vpc.internalConsumer" {
			t.Errorf("законный близнец получил находку: %v", f)
		}
	}
}

// TestCensusIsPrintedAndNonEmpty — «ноль находок» обязано быть отличимо от
// «ноль прочитанного».
func TestCensusIsPrintedAndNonEmpty(t *testing.T) {
	m := mustFixture(t)
	_, census := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))

	if census.RolesRead != 2 {
		t.Errorf("ролей осмотрено %d, в фикстуре две", census.RolesRead)
	}
	if census.PairsJudged == 0 {
		t.Error("пар (ресурс, класс) осмотрено ноль: вердикт беспредметен")
	}
	if s := census.Summary(); s == "" || !strings.Contains(s, "пар") {
		t.Errorf("перепись не печатает объём осмотренного: %q", s)
	}
}
