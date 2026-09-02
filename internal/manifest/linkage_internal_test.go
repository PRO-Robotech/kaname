// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// linkage_internal_test.go — MOD-MF-13: `roleId` выдачи обязан существовать
// среди ролей, объявленных ЭТИМ манифестом.
//
// # Здесь ИСТЕКЛО послабление #1088, и это надо сказать вслух
//
// Прежняя редакция файла разбирала сценарий ВНУТРИ пакета, подавая перечень
// ролей валидатору напрямую: раздел `roles` тогда отвергался разбором, и
// документа, объявляющего роли, не существовало ни при каком входе.
// Рядом стояла проба-предикат
// TestMODMF13RoleSetStaysUnwiredOnlyWhileTheSectionIsRefused — послабление,
// истекающее САМО: она краснела в тот день, когда раздел перестанет
// отвергаться, и называла починку своим текстом.
//
// День настал (#1778): раздел описан, перечень ролей приезжает ИЗ РАЗОБРАННОГО
// ДОКУМЕНТА, и проба-предикат снята ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ, а не ослаблена.
// Сценарий с этого дня выражается через прод-путь `Load` целиком — включая
// положительный контроль, ради которого он и жил внутри пакета.
package manifest

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// mustReadSeedFixture — тот же настоящий манифест, что читают остальные пробы
// пакета. Отдельное имя, потому что mustReadFixture объявлен соседним файлом
// проб и меняться вместе с ним эта проба не обязана.
func mustReadSeedFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/vpc.seed-fixture.yaml")
	if err != nil {
		t.Fatalf("чтение фикстуры: %v", err)
	}
	return string(data)
}

// declaredRolesSection — раздел `roles`, объявляющий обе роли, на которые
// ссылаются выдачи фикстуры посева. Пишется ЗДЕСЬ, а не в самой фикстуре:
// фикстура посева служит пробам, которым раздел ролей не нужен, и дописывать в
// неё чужой предмет значило бы менять вход у всех.
const declaredRolesSection = `
roles:
  - id: vpc.internalConsumer
    name: Смежный модуль
    description: Ходит в vpc на пути запроса — аллокация адресов и ссылки.
    tier: {tierType: iam.project, tierId: prj000000000000000}
    rules:
      - {module: vpc, resources: [address], verbs: [get, list]}
  - id: vpc.addressPoolAdmin
    name: Администратор адресного пространства
    description: Ведёт адресные пулы облака.
    tier: {tierType: iam.account, tierId: acc000000000000000}
    rules:
      - {module: vpc, resources: [addressPool], verbs: [get, list]}
`

// fixtureWithDeclaredRoles — фикстура посева ПЛЮС раздел ролей: документ, на
// котором положительный контроль MOD-MF-13 выразим прод-путём.
func fixtureWithDeclaredRoles(t *testing.T) string {
	t.Helper()
	return mustReadSeedFixture(t) + declaredRolesSection
}

// ── MOD-MF-13 ───────────────────────────────────────────────────────────────

// TestMODMF13RoleIDOutsideDeclaredRolesIsRefused — форма годна, роли нет.
//
// Схема на этом входе МОЛЧИТ (замер приёмки §2.3): образцу
// `^[a-z][a-zA-Z0-9]*\.[a-zA-Z][a-zA-Z0-9]*$` строка отвечает, и больше схеме
// сказать нечего. Свойство держит валидатор.
func TestMODMF13RoleIDOutsideDeclaredRolesIsRefused(t *testing.T) {
	doc := fixtureWithDeclaredRoles(t)
	if n := strings.Count(doc, "roleId: vpc.addressPoolAdmin"); n != 1 {
		t.Fatalf("образец встречается %d раз, инъекция требует ровно одного", n)
	}
	broken := strings.Replace(doc, "roleId: vpc.addressPoolAdmin", "roleId: vpc.nosuchRole", 1)

	_, err := Load([]byte(broken))
	if err == nil {
		t.Fatalf("выдача на роль, которой манифест не объявляет, принята")
	}
	if !errors.Is(err, ErrRoleNotDeclared) {
		t.Errorf("отказ не относится к виду ErrRoleNotDeclared: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"vpc.nosuchRole", "seed.accessBindings[1].roleId"} {
		if !strings.Contains(msg, want) {
			t.Errorf("отказ не называет %q: %s", want, msg)
		}
	}
	// Отказ обязан назвать и то, ЧЕМ он чинится: перечень объявленных ролей.
	if !strings.Contains(msg, "vpc.internalConsumer") {
		t.Errorf("отказ не называет объявленных ролей: %s", msg)
	}

	// Парный положительный: тот же документ с `roleId` из объявленных — ошибок
	// нет, и перепись говорит, что сверка ДЕЙСТВИТЕЛЬНО состоялась.
	m, err := Load([]byte(doc))
	if err != nil {
		t.Fatalf("выдача на объявленную роль отвергнута: %v", err)
	}
	c := m.Linkage()
	t.Logf("перепись связности при объявленных ролях: %s", c)
	if c.RoleRefsChecked != 2 || c.RoleRefsRead != 2 {
		t.Errorf("сверено %d ссылок из %d прочитанных — сверка не состоялась",
			c.RoleRefsChecked, c.RoleRefsRead)
	}
	if !c.RolesDeclared {
		t.Errorf("раздел объявлен, а перепись считает его необъявленным: %s", c)
	}
}

// TestMODMF13DeclaredButEmptyIsNotTheSameAsNotDeclared — состояний ТРИ, а не
// два, и разница наблюдаема ЧЕРЕЗ ПРОД-ПУТЬ.
//
// Раздел, объявленный пустым, есть утверждение автора «ролей у меня нет», и
// тогда всякая выдача ссылается в пустоту. Отсутствие раздела — не утверждение
// вовсе, и сверять не с чем. Схлопни их в одно — и правило замолчит ровно там,
// где автор ошибся: он написал `roles: []` и раздал права.
func TestMODMF13DeclaredButEmptyIsNotTheSameAsNotDeclared(t *testing.T) {
	seed := mustReadSeedFixture(t)

	empty, err := Load([]byte(seed + "\nroles: []\n"))
	if err == nil {
		t.Fatalf("роли объявлены пустым перечнем, а выдачи на них приняты: %+v", empty)
	}
	if !errors.Is(err, ErrRoleNotDeclared) {
		t.Errorf("отказ не относится к виду ErrRoleNotDeclared: %v", err)
	}

	notDeclared, err := Load([]byte(seed))
	if err != nil {
		t.Fatalf("раздел ролей не объявлен, сверять не с чем — а документ отвергнут: %v", err)
	}
	c := notDeclared.Linkage()
	if c.RolesDeclared {
		t.Errorf("раздел не объявлен, а перепись считает его объявленным: %s", c)
	}
	if c.RoleRefsChecked != 0 || c.RoleRefsRead != 2 {
		t.Errorf("сверено %d из %d — при необъявленном разделе сверяется ноль, и прочитано это должно быть двумя",
			c.RoleRefsChecked, c.RoleRefsRead)
	}
	// Перепись обязана СКАЗАТЬ, что ноль сверенных — это «не с чем сверять», а
	// не «сверили и не нашли расхождений».
	if !strings.Contains(c.String(), "раздел roles манифестом не объявлен") {
		t.Errorf("перепись молчит о том, почему сверено ноль: %s", c)
	}
}
