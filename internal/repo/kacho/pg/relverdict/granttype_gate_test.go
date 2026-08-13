// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Гейт словаря имён типа: колонку пишет один словарь, читает — тот же.
//
// ПРЕДМЕТ. Тип объекта называется в дереве двумя формами: формой модели прав
// (`vpc_network`, `account`) — ею приходит вопрос о доступе, — и точечной
// (`vpc.network`, `iam.account`) — ею писатель кладёт `role_verb.object_type` и
// `role_rule_selectors.object_types`. Соединение по разным написаниям не
// совпадает НИКОГДА, и это не отказ, а тишина: исход выглядит как «права нет».
//
// ПОЧЕМУ ГЕЙТ, А НЕ ВНИМАНИЕ. Расхождение видно только на данных, которые пишет
// прод; интеграционная проба с посевом «формой читателя» согласуется сама с
// собой и остаётся зелёной при любом переводчике — проверено инъекцией: пока
// посев и читатель звали ОДНУ функцию, подмена перевода не роняла ни одной
// пробы. Здесь сверяются словари, а не поведение на фикстуре.
package relverdict_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
)

// TestGrantTypeNameSpeaksTheDictionaryOfTheGrantTables — для КАЖДОГО типа
// каталога модели читатель обязан назвать точечную форму, потому что ею названы
// типы в таблицах выдачи.
func TestGrantTypeNameSpeaksTheDictionaryOfTheGrantTables(t *testing.T) {
	// Перечень типов ВЫВОДИТСЯ из каталога, а не выписывается: выписанный
	// разошёлся бы с ним молча — ровно тот класс, который здесь и ловится.
	entries := authzmap.Catalog()
	types := make([]string, 0, len(entries))
	for _, e := range entries {
		fgaType, ok := authzmap.ObjectType(e.Module, e.Resource)
		if !ok {
			t.Fatalf("каталог назвал пару %s.%s, для которой формы модели нет — "+
				"перечень и отображение разошлись", e.Module, e.Resource)
		}
		types = append(types, fgaType)
	}
	if len(types) == 0 {
		t.Fatal("каталог модели пуст: сверять нечего, и «ноль расхождений» здесь " +
			"означало бы «ноль прочитанного»")
	}

	var bad []string
	dotted := 0
	for _, fgaType := range types {
		want, known := authzmap.DottedType(fgaType)
		if !known {
			// Тип каталога без точечного имени — предмет другого гейта; здесь он
			// не находка, но и в знаменатель не идёт.
			continue
		}
		dotted++
		got := relverdict.GrantTypeName(fgaType)
		if got != want {
			bad = append(bad, fgaType+": читатель говорит "+got+", таблицы выдачи — "+want)
		}
		if !strings.Contains(want, ".") {
			bad = append(bad, fgaType+": точечная форма без точки — "+want)
		}
	}

	t.Logf("осмотрено: типов каталога %d, из них с точечным именем %d", len(types), dotted)
	if dotted == 0 {
		t.Fatal("ни один тип каталога не имеет точечного имени — предикат ничего не сверил")
	}
	if len(bad) != 0 {
		t.Fatalf("%d тип(ов) читаются не тем словарём, каким пишутся:\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
}

// TestGrantTypeNamePassesUnknownTypeThrough — тип вне каталога возвращается КАК
// ЕСТЬ, а не пустой строкой: пустая подстановка совпала бы с пустым значением
// колонки и превратила бы «типа не знаем» в «право есть».
func TestGrantTypeNamePassesUnknownTypeThrough(t *testing.T) {
	const alien = "no_such_type_in_the_catalogue"
	if got := relverdict.GrantTypeName(alien); got != alien {
		t.Fatalf("неизвестный тип изменён: %q → %q; ожидалось сквозное прохождение", alien, got)
	}
	if got := relverdict.GrantTypeName(""); got != "" {
		t.Fatalf("пустой вход изменён: %q — подстановка не должна ничего выдумывать", got)
	}
}
