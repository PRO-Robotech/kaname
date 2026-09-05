// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicauthzcensus_test

// census_test.go — гейт: публичный RPC iam без ПООБЪЕКТНОГО вопроса о доступе
// есть находка.
//
// Предмет назван в шапке пакета: вынесенный в чужое облако iam нашего края не
// имеет, и каждый публичный RPC без собственной двери отдаёт чужой объект
// аутентифицированному арендатору.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/publicauthzcensus"
)

func TestEveryPublicRPCCarriesAnObjectQuestion(t *testing.T) {
	root := repoRoot(t)
	c, err := publicauthzcensus.Collect(root)
	if err != nil {
		t.Fatalf("перепись не состоялась: %v", err)
	}
	t.Log(c.Summary())

	// Пустой обход — «беспредметно», а не «чисто». Обе величины требуются:
	// знаменатель без разобранных файлов означал бы, что контракт прочитан, а
	// код — нет, и тогда КАЖДЫЙ RPC оказался бы находкой по недосмотру.
	if c.Inspected == 0 {
		t.Fatal("обход пуст: публичных RPC осмотрено 0 — вердикт беспредметен")
	}
	if c.GoFiles == 0 {
		t.Fatal("обход пуст: файлов Go разобрано 0 — вердикт беспредметен")
	}

	// «Не разрешилось» — третья категория. Она не вычитается из вердикта и не
	// зачитывается в успех: RPC, чей обслуживающий путь не разобран, не имеет
	// вердикта ВООБЩЕ, и молчание о нём было бы выдачей незнания за норму.
	if len(c.Unresolved) > 0 {
		var names []string
		for _, r := range c.Unresolved {
			names = append(names, r.String())
		}
		t.Errorf("не разрешилось %d публичных RPC — вердикта по ним нет:\n  %s",
			len(c.Unresolved), strings.Join(names, "\n  "))
	}

	// Карта прав обязана быть выведена. Ноль записей означает, что о двери не
	// известно ничего, и тогда «покрыто» ниже было бы утверждением ни о чём.
	if c.MapEntries == 0 {
		t.Fatal("карта прав двери пуста: о покрытии не известно ничего")
	}

	ungated := map[string]bool{}
	for _, r := range c.InCategory(publicauthzcensus.CategoryUngated) {
		ungated[r.String()] = true
	}

	declared := publicauthzcensus.DeclaredRemainder()

	// (а) Ведомость записана ПО ФАКТУ, а не потолком: запись, которой больше
	// нечего прощать, — находка. Иначе послабление не истечёт никогда, оставаясь
	// на вид рабочим, и следующая настоящая дыра уедет под него незамеченной.
	var stale []string
	for rpc := range declared {
		if !ungated[rpc] {
			stale = append(stale, rpc)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("ведомость остатка прощает %d RPC, у которых дверь УЖЕ есть — снимите записи:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}

	// (б) Новая дыра не заводится молча.
	var undeclared []string
	for rpc := range ungated {
		if !declared[rpc] {
			undeclared = append(undeclared, rpc)
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Errorf("публичных RPC БЕЗ двери: %d из %d осмотренных.\n"+
			"Вынесенный iam края не имеет — каждый из них отдаёт объект любому "+
			"аутентифицированному вызывающему:\n  %s",
			len(undeclared), c.Inspected, strings.Join(undeclared, "\n  "))
	}

	// Освобождённые контрактом НАЗЫВАЮТСЯ, а не молчат: на вынесенном iam это
	// вся оставшаяся поверхность, к которой пообъектного вопроса не задаётся, и
	// «их шесть» обязано быть видно без чтения кода. Находкой это не является —
	// освобождение записано в контракте и рецензировалось.
	exempt := c.InCategory(publicauthzcensus.CategoryExempt)
	names := make([]string, 0, len(exempt))
	for _, r := range exempt {
		names = append(names, r.String())
	}
	sort.Strings(names)
	t.Logf("освобождены контрактом от пообъектного вопроса (%d): %s",
		len(names), strings.Join(names, ", "))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль (она выносится отдельным репозиторием), и подъём «до
	// первого» останавливался бы в её каталоге. Пути, которые ниже склеиваются с
	// этим корнем, называют место В ДЕРЕВЕ МОНОРЕПО — от корня, — поэтому
	// остановка внутри службы удваивала сегмент и обход искал `services/iam/
	// services/iam/…`, которого не существует.
	outermost := ""
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return outermost
			}
			t.Fatal("не найден корень репозитория (каталог с go.mod)")
		}
		dir = parent
	}
}
