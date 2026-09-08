// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_absent_test.go — разбор «контур бутстрап-удостоверения не достаёт до
// поставщика НИ ОДНИМ портом» (задача #1119, Ф4б эпика #896).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПРОБА ПОВЕДЕНИЯ
//
// Проба поведения отвечает на вопрос «позвали ли поставщика в ЭТОМ сценарии».
// Предикат снятия задаёт другой вопрос — «есть ли к нему дорога вообще», — и
// ответ на него есть свойство ДЕРЕВА, а не одного прогона: порт, который сегодня
// не зовут, завтра зовут одной строкой, и ни одна проба поведения от этого не
// покраснеет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ИЗМЕРЯЕТСЯ ДОРОГА
//
// Ребром импорта на пакет клиентов поставщика. Разговор с ним ведётся ТОЛЬКО
// через этот пакет (там живут его пути и его транспорт), поэтому отсутствие
// ребра означает отсутствие дороги — включая ту, которую завели бы «на будущее»
// и не позвали ни разу.
//
// Предикат по слову «hydra» тут негоден: слово законно в именах настроек, в
// комментариях о самом переезде и в применённых миграциях — гейт по нему
// краснел бы на исправном дереве.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА
//
// Гейт не поймает обращение к поставщику, собранное в обход этого пакета —
// голым http-клиентом по адресу из настройки. Такого предиката не существует;
// рост поверхности этим способом держит ведомость
// `internal/repohygiene` (providersurface.go), а не эта проба.
package bootstraptokenwire

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// providerClientPkg — пакет клиентов внешнего поставщика удостоверений.
const providerClientPkg = "github.com/PRO-Robotech/kaname/internal/clients"

// bootstrapMintPackages — каталоги, составляющие путь чеканки бутстрапа:
// use-case и его композиция. Пути относительны каталогу ЭТОГО пакета, поэтому
// проба не зависит ни от корня дерева, ни от git.
var bootstrapMintPackages = []string{
	".",                                  // bootstraptokenwire — сборка контура
	"../apps/kaname/api/bootstrap_token", // use-case чеканки
}

// providerImportsIn возвращает файлы каталога, импортирующие пакет поставщика,
// и число прочитанных файлов.
//
// Тестовое дерево не рассматривается намеренно: предмет запрета — дорога,
// которой пойдёт ПРОЦЕСС, а подставной клиент в пробе процессом не является.
func providerImportsIn(t *testing.T, dir string) (found []string, filesRead int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("каталог %s не прочитан: %v — «ноль находок» здесь означало бы «ноль прочитанного»", dir, err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("разбор %s: %v", path, perr)
		}
		filesRead++
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if p == providerClientPkg {
				found = append(found, path)
				break
			}
		}
	}
	return found, filesRead
}

// TestBootstrapMintHasNoRoadToTheProvider — у контура чеканки бутстрапа нет
// дороги к поставщику ни на заведение клиента, ни на обмен утверждения.
func TestBootstrapMintHasNoRoadToTheProvider(t *testing.T) {
	total := 0
	var findings []string
	for _, dir := range bootstrapMintPackages {
		found, read := providerImportsIn(t, dir)
		total += read
		findings = append(findings, found...)
	}
	// Объём осмотренного печатается ВСЕГДА: без него «ноль находок» неотличимо
	// от «каталоги не те и прочитано ноль файлов».
	t.Logf("перепись: каталогов %d · файлов прод-кода прочитано %d · дорог к поставщику %d",
		len(bootstrapMintPackages), total, len(findings))
	if total == 0 {
		t.Fatal("прочитано ноль файлов прод-кода — проба беспредметна, а не зелена")
	}
	if len(findings) != 0 {
		t.Fatalf("контур чеканки бутстрапа достаёт до поставщика через %s:\n  %s\n"+
			"бутстрап — единственное удостоверение, которым кластер поднимают с нуля, "+
			"и оно обязано быть исполнимо без внешней стороны",
			providerClientPkg, strings.Join(findings, "\n  "))
	}
}
