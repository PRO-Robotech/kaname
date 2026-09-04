// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// roleclasses_test.go — ГЛАВНАЯ ФОРМА права роли: ключ `classes`
// (приёмка `classes-form-of-role-right.md`, §3.1–§3.3, сценарии
// MOD-RC-01 … MOD-RC-05, MOD-RC-11).
//
// # Что здесь проверяется, а что намеренно НЕТ
//
// Загрузчик судит ФОРМУ: ключ, тип, мощность. Значение — покрывает ли класс
// хотя бы одно пригодное действие ресурса — судит стадия 1 (`roleexport`), и
// её сценарии живут у неё (MOD-RC-09, MOD-RC-10, MOD-RC-12). Закрытой проверки
// набора классов на ЗАГРУЗКЕ нет, и это решение §3.1, а не пропуск: словарь
// снятых имён принадлежит самому манифесту, поэтому «вне обоих словарей» есть
// суждение о значении.
//
// # Ожидание MOD-RC-02 берётся у ВНЕШНЕГО артефакта
//
// Литерал рядом с пробой был бы вторым написанием того же предмета и разошёлся
// бы с миграцией молча. Поэтому ожидание читается ИЗ применённой миграции
// `0031_reseed_system_roles_rules.sql` — из строк живых ролей `vpc.network.view`
// и `vpc.network.edit`.
package manifest_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// roleManifest — манифест с одним правилом роли, записанным дословно.
//
// Нотация ЗАГРУЖАЕМАЯ: `module` обязателен, ключ ресурсов — `resources` во
// множественном числе. Черновиковая запись (`resource:`, `grants:`) схемой не
// знается и до предмета этих проб не доходит вовсе.
func roleManifest(rule string) string {
	return "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.viewer\n    description: Читает топологию сетей проекта.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - " + rule + "\n"
}

// ── MOD-RC-01 ───────────────────────────────────────────────────────────────

// TestMODRC01ClassesKeyIsTheFormOfARoleRight — основная форма загружается.
func TestMODRC01ClassesKeyIsTheFormOfARoleRight(t *testing.T) {
	m, err := manifest.Load([]byte(roleManifest("{module: vpc, resources: [network], classes: [get]}")))
	if err != nil {
		t.Fatalf("основная форма права роли отвергнута: %v", err)
	}
	if len(m.Roles) != 1 || len(m.Roles[0].Rules) != 1 {
		t.Fatalf("ролей %d, правил у первой %d — ожидалась одна роль с одним правилом",
			len(m.Roles), len(m.Roles[0].Rules))
	}
	if got := m.Roles[0].Rules[0].Classes; !reflect.DeepEqual(got, []string{"get"}) {
		t.Errorf("значение ключа classes прочитано как %#v, в документе [get]", got)
	}
}

// ── MOD-RC-02 ───────────────────────────────────────────────────────────────

// migrationRuleVerbs — глаголы права живой роли, прочитанные ИЗ ПРИМЕНЁННОЙ
// МИГРАЦИИ.
//
// Ожидание берётся у внешнего артефакта, а не у литерала рядом: второе
// написание того же предмета разошлось бы с первым молча. Разбор — по строке
// `UPDATE … rules = '<json>' … md5('<роль>')`, то есть по тому, что миграция
// реально кладёт в строку.
func migrationRuleVerbs(t *testing.T, roleID string) []string {
	t.Helper()
	// Ожидание берётся у ПРИМЕНЁННОЙ схемы, и координата у неё теперь одна:
	// цепочка iam сведена в первичную миграцию (2026-09-04). Прежде здесь стоял
	// файл `0031_reseed_system_roles_rules.sql`, который правил столбец
	// оператором `UPDATE … SET rules = … WHERE id = 'rol' || substr(md5(…))`.
	// Свод несёт КОНЕЧНОЕ состояние: роль вставляется разом, идентификатор уже
	// вычислен, а правило стоит значением столбца. Разбор поэтому ищет роль по
	// ИМЕНИ — величине, которая не зависит ни от способа вывода
	// идентификатора, ни от того, каким оператором строка получила своё правило.
	const path = "../migrations/0001_initial.sql"
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("применённая миграция не прочитана: %v", err)
	}
	hit := roleRulesFromSeed(string(body), roleID)
	if hit == nil {
		t.Fatalf("в миграции %s не найдено строки роли %q — ожидание брать неоткуда, "+
			"и «ноль расхождений» стало бы свойством разбора, а не дерева", path, roleID)
	}
	var rules []struct {
		Verbs []string `json:"verbs"`
	}
	if err := json.Unmarshal([]byte(hit[1]), &rules); err != nil {
		t.Fatalf("право роли %q из миграции не разобрано: %v", roleID, err)
	}
	if len(rules) != 1 {
		t.Fatalf("у роли %q в миграции правил %d, ожидалось одно", roleID, len(rules))
	}
	return rules[0].Verbs
}

// TestMODRC02TranslationIsWordForWordAgainstTheAppliedMigration — перевод
// `classes → domain.Rule.Verbs` ТОЖДЕСТВЕН, и ожидание внешнее.
//
// Отрицательный контроль внутри сценария: приведение снятого глагола к его
// классу дало бы `["get","list","get"]` — не равно строке миграции, и сравнение
// обязано на этом покраснеть.
func TestMODRC02TranslationIsWordForWordAgainstTheAppliedMigration(t *testing.T) {
	// Классы фикстуры взяты у ЖИВЫХ ролей посева, а не у промежуточного шага.
	//
	// Прежде ожидание бралось из `0031_reseed_system_roles_rules.sql` — снимка
	// СЕРЕДИНЫ цепочки. Более поздние миграции правили тот же столбец (у `view`
	// снят снятый глагол `read`, у `edit` прибавились `get` и `list`), и файл
	// перестал быть живой правдой ещё тогда. Проба этого не замечала: она читала
	// замороженный файл и потому оставалась зелёной, сверяясь с состоянием,
	// которого в базе давно нет, — утверждение, пережившее свой предмет.
	// Сведение цепочки (2026-09-04) сделало это видимым: координата исчезла, а
	// живой посев назвал другие глаголы.
	m, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.viewer\n    description: Читает топологию сетей проекта.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n" +
		"      - {module: vpc, resources: [network], classes: [list, get]}\n" +
		"      - {module: vpc, resources: [network], classes: [get, list, update]}\n" +
		"deprecatedVerbs:\n" +
		"  read:\n    class: get\n    since: \"2026-08-23\"\n" +
		"    reason: Синоним чтения из прежней грамматики.\n" +
		"    removeWhen: Выдач с правом `.read` ноль.\n"))
	if err != nil {
		t.Fatalf("манифест отвергнут: %v", err)
	}
	if len(m.Roles[0].Rules) != 2 {
		t.Fatalf("правил прочитано %d, в документе два", len(m.Roles[0].Rules))
	}

	for i, roleID := range []string{"vpc.network.view", "vpc.network.edit"} {
		want := migrationRuleVerbs(t, roleID)
		got := m.Roles[0].Rules[i].DomainRule().Verbs
		if !reflect.DeepEqual(got, want) {
			t.Errorf("перевод правила %d дал %#v, а живая роль %q применённой миграции "+
				"несёт %#v: перевод обязан быть ДОСЛОВНЫМ — приведение снятого глагола "+
				"к классу сделало бы строку невоспроизводимой", i, got, roleID, want)
		}
	}
	t.Logf("перепись: правил переведено %d · ожиданий взято у посева %d",
		len(m.Roles[0].Rules), 2)

	// ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ — отдельным утверждением, а не входом сверки выше.
	//
	// Он про то, что перевод НЕ приводит снятый глагол к его классу: `read`
	// объявлен снятым с классом `get`, и схлопывание дало бы `["get","list"]`
	// вместо `["read","list"]`. Прежде контроль ехал внутри той же фикстуры и
	// потому требовал, чтобы `read` стоял в живой роли; живая роль его больше не
	// несёт — и это правильно, глагол снимается. Свойство переводчика от этого
	// не изменилось, поэтому контроль остаётся, но со СВОИМ входом: он про
	// перевод, а не про согласие с посевом.
	dep, derr := manifest.Load([]byte("apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.legacy\n    description: Несёт снятый глагол дословно.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n" +
		"      - {module: vpc, resources: [network], classes: [read, list]}\n" +
		"deprecatedVerbs:\n" +
		"  read:\n    class: get\n    since: \"2026-08-23\"\n" +
		"    reason: Синоним чтения из прежней грамматики.\n" +
		"    removeWhen: Выдач с правом `.read` ноль.\n"))
	if derr != nil {
		t.Fatalf("манифест со снятым глаголом отвергнут: %v", derr)
	}
	if got, want := dep.Roles[0].Rules[0].DomainRule().Verbs, []string{"read", "list"}; !reflect.DeepEqual(got, want) {
		t.Errorf("снятый глагол приведён к своему классу: перевод дал %#v, ожидалось %#v — "+
			"строка стала бы невоспроизводимой, а посев неотличим от того, что его породило",
			got, want)
	}
}

// ── MOD-RC-03 и MOD-RC-04 — СНЯТЫ ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ (kacho#1844) ────
//
// Оба утверждали ОТСУТСТВИЕ: ключ `verbs` в правиле роли отвергается, и наличие
// `classes` его не легализует. Предмет обоих — пред-разборный отказ
// `refuseRuleVerbs` — снят: поимённая форма права вернулась вместе с проверкой
// её полноты по классу, ровно как предписывал §10 п. 2 приёмки
// `classes-form-of-role-right.md`, снимавшей ключ.
//
// Снято, а не ослаблено, и это ВАЖНО: негативное утверждение, лишившееся
// предмета, ЗАМОЛКАЕТ — вход, на котором оно находит нарушение, перестаёт быть
// представимым, ветвь остаётся, счётчик утверждений растёт, вердикт зелёный.
// Отличить это от исправной работы нельзя ничем (`testing.md` §«Снимая ПРЕДМЕТ,
// разбери проверки по ЗНАКУ утверждения»).
//
// Что от них ОСТАЛОСЬ и где живёт: взаимоисключаемость двух форм (§3.1) —
// `rolenamedverbs_test.go`, `TestNamedAndClassFormsDoNotStandTogether`, с двумя
// парными положительными по одному на форму. Она и есть наследник MOD-RC-04:
// его предмет («вторая запись не уезжает молча») жив, сменился лишь отвергаемый
// вход.

// ── MOD-RC-05 ───────────────────────────────────────────────────────────────

// TestMODRC05EmptyClassListIsRefusedByTheDomain — мощность судит ДОМЕН, а не
// копия его правил в манифесте.
func TestMODRC05EmptyClassListIsRefusedByTheDomain(t *testing.T) {
	_, err := manifest.Load([]byte(roleManifest("{module: vpc, resources: [network], classes: []}")))
	if err == nil {
		t.Fatal("пустой перечень классов принят")
	}
	if !errors.Is(err, manifest.ErrRoleRuleInvalid) {
		t.Errorf("отказ мощности пришёл не от домена: %v", err)
	}
	if !strings.Contains(err.Error(), "Illegal argument verbs (must be non-empty)") {
		t.Errorf("текст отказа не дословный текст домена — тексты отказов часть контракта: %v", err)
	}

	// Парный положительный.
	if _, err := manifest.Load([]byte(roleManifest(
		"{module: vpc, resources: [network], classes: [get]}"))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-RC-11 ───────────────────────────────────────────────────────────────

// TestMODRC11UnknownKeyInsideARoleRuleIsStillRefused — строгость по ОСТАЛЬНЫМ
// ключам правила СОХРАНЕНА.
//
// Свойство не заводится этой работой, а сохраняется, — и потому проба
// обязательна: утраченная строгость и целая молчат одинаково. Инъекция И8
// (свой `Rule.UnmarshalYAML` вместо пред-разборного отказа) обязана ронять
// именно её.
func TestMODRC11UnknownKeyInsideARoleRuleIsStillRefused(t *testing.T) {
	_, err := manifest.Load([]byte(roleManifest(
		"{module: vpc, resources: [network], classes: [get], resourceNamez: [ntw-1]}")))
	if err == nil {
		t.Fatal("опечатка в имени ключа правила принята: ключ уехал бы молча")
	}
	if !errors.Is(err, manifest.ErrShape) {
		t.Errorf("отказ не отнесён к форме документа: %v", err)
	}
	for _, want := range []string{"resourceNamez", "line "} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Парный положительный: то же правило без лишнего ключа — принимается.
	if _, err := manifest.Load([]byte(roleManifest(
		"{module: vpc, resources: [network], classes: [get], resourceNames: [ntw-1]}"))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// reSeededRole — строка посева роли: `pg_dump` печатает по одной на запись, все
// колонки перечислены, значения готовы. Захватываются ИМЯ (третье значение) и
// правило — единственный на строке массив объектов JSON.
var reSeededRole = regexp.MustCompile(
	`INSERT INTO kacho_iam\.roles \([^)]*\) VALUES \('[^']*', [^,]*, '([^']*)'.*?'(\[\{.*?\}\])'`)

// roleRulesFromSeed — правило роли по её ИМЕНИ, из посева сведённой миграции.
//
// Возвращает срез той же формы, что прежний разбор по образцу: nil, когда роли
// нет, иначе элемент [1] — текст массива правил. Форма сохранена намеренно,
// чтобы вызывающий и его сообщение об отсутствии остались прежними.
func roleRulesFromSeed(body, roleID string) []string {
	for _, m := range reSeededRole.FindAllStringSubmatch(body, -1) {
		if m[1] == roleID {
			return []string{m[0], m[2]}
		}
	}
	return nil
}
