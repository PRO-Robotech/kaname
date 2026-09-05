// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Непрерывный fuzzing — грамматика разрешения в роли.
//
// Разрешение записывается автором роли и хранится строкой вида
// `<модуль>.<ресурс>.<объект>.<действие>`, где любой сегмент может быть
// подстановочным знаком. Разбирает её `domain.Permission.Validate` (регулярное
// выражение), а та же грамматика продублирована проверкой на стороне БД —
// поэтому строка, проскочившая здесь, доедет до хранилища прав.
//
// Цель гоняет НАСТОЯЩИЕ `domain.Permission.Validate` и
// `domain.Permissions.Validate`/`ValidateCompiled`. Прежняя редакция звала
// локальную `isValidPermission`, которая (а) требовала ТРИ сегмента вместо
// четырёх, то есть описывала не ту грамматику, и (б) была объявлена рядом в том
// же файле, так что расхождение с продуктом не могло проявиться.
//
// Проверка идёт против НЕЗАВИСИМОГО признака, а не против самого выражения:
// принятая строка обязана состоять ровно из четырёх непустых сегментов и не
// содержать ничего, кроме букв, цифр, `_`, `-` и подстановочного знака.
// Повторять регулярное выражение в проверке бессмысленно — так проверялось бы
// его совпадение с самим собой. Смысл признака в том, что расширение выражения
// (перевод строки в конце, разделитель внутри сегмента, управляющий символ)
// меняет то, ЧТО означает разрешение, и обязано быть замечено, а не принято
// молча.
package fuzz_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// permissionRunes — алфавит, которым исчерпывается принимаемая грамматика.
const permissionRunes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-*"

func FuzzPermissionCatalogLookup(f *testing.F) {
	seeds := []string{
		"iam.user.*.read",
		"compute.diskType.*.list",
		"vpc.subnet.subnet-1.delete",
		"vpc.subnet.my_subnet.update",
		"load-balancer.nlb.*.create",
		"*.*.*.*",
		// Отвергаемые формы.
		"iam.user.*.Read",
		"iam.user.*.1read",
		"iam.User.*.read",
		"",
		"a.b.c",
		"a.b",
		"a.b.c.d.e",
		// Расширение грамматики через хвост и управляющие символы — именно то,
		// на что смотрит независимый признак.
		"iam.user.*.read\n",
		"iam.user.*.read\n.evil.x.y",
		"iam.user.*.read\x00",
		"iam.user.*.read ",
		" iam.user.*.read",
		"iam.user..read",
		"iam.user.*.read.",
		// Нагрузка на разбор.
		strings.Repeat("a.", 1000) + "z",
		strings.Repeat(".", 10000),
		strings.Repeat("iam.user.*.read", 500),
		"iam.user.*." + strings.Repeat("a", 100000),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ПАНИКА на разрешении %q: %v", input, r)
			}
		}()

		perm := domain.Permission(input)
		err := perm.Validate()

		if err == nil {
			assertPermissionShape(t, input)
		}

		// Набор из одного элемента обязан решать так же, как элемент: расхождение
		// означает, что роль принимает разрешение, которое поэлементно отвергнуто
		// (или наоборот).
		single := domain.Permissions{perm}
		if (single.Validate() == nil) != (err == nil) {
			t.Fatalf("набор из одного разрешения и само разрешение решают по-разному "+
				"для %q: элемент err=%v, набор err=%v", input, err, single.Validate())
		}
		if (single.ValidateCompiled() == nil) != (err == nil) {
			t.Fatalf("собранный набор и элемент решают по-разному для %q: элемент err=%v, "+
				"набор err=%v", input, err, single.ValidateCompiled())
		}

		// Пустой набор допустим только для собранного из правил (роль из одних
		// меток собирается в пустой набор), но не для роли, записанной списком.
		if domain.Permissions(nil).Validate() == nil {
			t.Fatal("роль, записанная списком разрешений, принята с пустым списком — " +
				"такая роль не даёт ничего и не может быть выражена списком")
		}
		if err := domain.Permissions(nil).ValidateCompiled(); err != nil {
			t.Fatalf("собранный из правил пустой набор отвергнут (%v) — роль из одних "+
				"меток собирается именно в него", err)
		}
	})
}

// assertPermissionShape — независимый признак принятой строки: ровно четыре
// непустых сегмента и ни одного символа вне алфавита грамматики.
func assertPermissionShape(t *testing.T, input string) {
	t.Helper()

	parts := strings.Split(input, ".")
	if len(parts) != 4 {
		t.Fatalf("принято разрешение %q из %d сегментов вместо четырёх — адресуемая "+
			"часть разрешения читается не там, где ожидает проверка прав", input, len(parts))
	}
	for i, p := range parts {
		if p == "" {
			t.Fatalf("принято разрешение %q с пустым сегментом %d", input, i)
		}
	}
	for _, r := range input {
		if r == '.' {
			continue
		}
		if !strings.ContainsRune(permissionRunes, r) {
			t.Fatalf("принято разрешение %q с символом %q вне алфавита грамматики — "+
				"перевод строки, пробел или управляющий символ в разрешении меняет то, "+
				"что оно означает", input, r)
		}
	}
}
