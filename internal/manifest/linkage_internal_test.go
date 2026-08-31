// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// linkage_internal_test.go — MOD-MF-13: `roleId` выдачи обязан существовать
// среди ролей, объявленных ЭТИМ манифестом.
//
// # Почему сценарий разбирается ВНУТРИ пакета, а не через Load
//
// Раздел `roles` эта под-фаза не описывает и отвергает явно (MOD-MF-07,
// задача-преемник PRO-Robotech/kacho#1778). Значит документа, объявляющего роли,
// сегодня не существует ни при каком входе — а положительный контроль MOD-MF-13
// требует ровно его: «тот же манифест с `roleId` из `roles` — ошибок нет».
//
// Отсюда два следствия, и оба названы прямо, а не умолчаны:
//
//  1. правило нельзя применять безусловно. Манифест не объявляет ролей ни при
//     каком входе, поэтому безусловная проверка отвергала бы КАЖДУЮ выдачу — и
//     первым покраснел бы неиспорченный черновик, то есть контроль MOD-MF-16;
//  2. состояний у перечня ролей ТРИ, а не два: «раздел не объявлен» ·
//     «объявлен и пуст» · «объявлен с перечнем». Первое означает «сверять не с
//     чем», второе — «сверять не с чем, и это сказано автором», и смешение их
//     дало бы правило, которое молчит на пустом перечне.
//
// Механизм проверки при этом ЖИВОЙ и доказан инъекцией: перечень подаётся
// валидатору напрямую тем же прод-путём (`loadWithRoles`), которым его подаст
// разбор, когда раздел `roles` будет описан. Проба-предикат ниже краснеет в тот
// день, когда раздел перестанет отвергаться, и требует провязать перечень.
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

// declaredRolesOfTheFixture — роли, которые объявляет тот же документ черновика
// разделом `roles`. Здесь они подаются перечнем, потому что раздел отвергается
// разбором: см. шапку файла.
func declaredRolesOfTheFixture() roleIDs {
	return rolesDeclared("vpc.internalConsumer", "vpc.addressPoolAdmin")
}

// ── MOD-MF-13 ───────────────────────────────────────────────────────────────

// TestMODMF13RoleIDOutsideDeclaredRolesIsRefused — форма годна, роли нет.
//
// Схема на этом входе МОЛЧИТ (замер приёмки §2.3): образцу
// `^[a-z][a-zA-Z0-9]*\.[a-zA-Z][a-zA-Z0-9]*$` строка отвечает, и больше схеме
// сказать нечего. Свойство держит валидатор.
func TestMODMF13RoleIDOutsideDeclaredRolesIsRefused(t *testing.T) {
	doc := mustReadSeedFixture(t)
	if n := strings.Count(doc, "vpc.addressPoolAdmin"); n != 1 {
		t.Fatalf("образец встречается %d раз, инъекция требует ровно одного", n)
	}
	broken := strings.Replace(doc, "vpc.addressPoolAdmin", "vpc.nosuchRole", 1)

	_, err := loadWithRoles([]byte(broken), declaredRolesOfTheFixture())
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
	m, err := loadWithRoles([]byte(doc), declaredRolesOfTheFixture())
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
		t.Errorf("перечень ролей подан, а перепись считает его необъявленным: %s", c)
	}
}

// TestMODMF13DeclaredButEmptyIsNotTheSameAsNotDeclared — состояний ТРИ, а не
// два, и разница наблюдаема.
//
// Раздел, объявленный пустым, есть утверждение автора «ролей у меня нет», и
// тогда всякая выдача ссылается в пустоту. Отсутствие раздела — не утверждение
// вовсе, и сверять не с чем. Схлопни их в одно — и правило замолчит ровно там,
// где автор ошибся: он написал `roles: []` и раздал права.
func TestMODMF13DeclaredButEmptyIsNotTheSameAsNotDeclared(t *testing.T) {
	doc := mustReadSeedFixture(t)

	empty, err := loadWithRoles([]byte(doc), rolesDeclared())
	if err == nil {
		t.Fatalf("роли объявлены пустым перечнем, а выдачи на них приняты: %+v", empty)
	}
	if !errors.Is(err, ErrRoleNotDeclared) {
		t.Errorf("отказ не относится к виду ErrRoleNotDeclared: %v", err)
	}

	notDeclared, err := loadWithRoles([]byte(doc), rolesNotDeclared())
	if err != nil {
		t.Fatalf("раздел ролей не объявлен, сверять не с чем — а документ отвергнут: %v", err)
	}
	c := notDeclared.Linkage()
	if c.RolesDeclared {
		t.Errorf("перечень не подан, а перепись считает его объявленным: %s", c)
	}
	if c.RoleRefsChecked != 0 || c.RoleRefsRead != 2 {
		t.Errorf("сверено %d из %d — при необъявленном разделе сверяется ноль, и прочитано это должно быть двумя",
			c.RoleRefsChecked, c.RoleRefsRead)
	}
	// Перепись обязана СКАЗАТЬ, что ноль сверенных — это «не с чем сверять», а
	// не «сверили и не нашли расхождений».
	if !strings.Contains(c.String(), "раздел roles не описан") {
		t.Errorf("перепись молчит о том, почему сверено ноль: %s", c)
	}
}

// TestMODMF13RoleSetStaysUnwiredOnlyWhileTheSectionIsRefused — послабление,
// истекающее САМО.
//
// Загрузчик подаёт валидатору «раздел не объявлен» ровно потому, что раздел
// `roles` отвергается разбором. Как только он перестанет отвергаться, эта проба
// краснеет и называет, что провязать: перечень ролей обязан приехать из
// разобранного документа, а не остаться необъявленным.
//
// Без такой пробы послабление не истекло бы никогда: оно выглядит исправной
// работой и на зелёном прогоне неотличимо от провязанного перечня.
func TestMODMF13RoleSetStaysUnwiredOnlyWhileTheSectionIsRefused(t *testing.T) {
	if !contains(sectionsNotDescribedYet, "roles") {
		t.Fatalf("раздел `roles` больше не отвергается разбором — значит документ может " +
			"объявить роли, и Load обязан подать их валидатору вместо rolesNotDeclared(): " +
			"провяжите перечень в loadWithRoles и снимите эту пробу вместе с послаблением")
	}

	// Предмет послабления измеряется, а не объявляется: документ с разделом
	// `roles` отвергается разбором, поэтому производителя перечня у Load нет.
	doc := mustReadSeedFixture(t) + "\nroles:\n  - id: vpc.internalConsumer\n"
	if _, err := Load([]byte(doc)); !errors.Is(err, ErrSectionNotDescribed) {
		t.Fatalf("документ с разделом `roles` обязан отвергаться разбором, получено: %v", err)
	}

	// И вторая половина: сам Load подаёт именно «не объявлено» — иначе
	// послабление жило бы не там, где эта проба его сторожит.
	m, err := Load([]byte(mustReadSeedFixture(t)))
	if err != nil {
		t.Fatalf("фикстура отвергнута: %v", err)
	}
	if m.Linkage().RolesDeclared {
		t.Errorf("Load объявил перечень ролей подданным, хотя раздел отвергается разбором")
	}
}
