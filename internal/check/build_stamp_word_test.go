// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// build_stamp_word_test.go — слово «сборка штамп не проставила» у платформы и
// у службы доступа ОДНО, хотя объявлений два (держатель,
// названный `docs/engineering/acceptance/seed-identity-names-its-own-service.md`
// §6 — `TestBuildStampWordMatchesThePlatformWord`).
//
// # Предмет
//
// Ряд `*_build_info` держат несколько процессов платформы и процесс службы
// доступа, и на непроставленном штампе каждый обязан ответить одним и тем же
// словом. Дежурный сверяет витрины разных процессов не пересчитывая; два
// написания одного состояния означали бы две тревоги об одном предмете, и
// одна из них однажды не будет написана.
//
// # Почему два объявления, а не одно — и почему это не лень
//
// Служба доступа — отдельный Go-модуль, зависящий от платформы пином
// (`go.mod`: `github.com/PRO-Robotech/kacho v0.1.0`). Общей константы у них
// быть не может: правка слова в платформе доехала бы до службы только со
// следующим бампом пина — то есть молча и не тогда. Значит объявления два по
// построению, а держит их согласие этот гейт.
//
// # Читается объявление, а не текст
//
// Слово `unstamped` стоит в прозе — в шапках, в документации службы и в этом
// файле. Поиск по подстроке нашёл бы собственное объяснение и остался бы
// зелёным при разошедшихся объявлениях. Поэтому значение берётся разбором
// синтаксического дерева: узел объявления константы, а не строка файла
// (`ConstStringValue` в `build_stamp_word.go`).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `build_stamp_word_injection_test.go`.
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/observability"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// ownBuildStampWordFile — где служба доступа объявляет своё слово, ОТНОСИТЕЛЬНО
// корня СВОЕГО модуля (не дерева платформы: сверяемая половина — скомпилированная
// зависимость `pkg/observability`, а не исходники платформы, поэтому обход
// платформенного дерева здесь не нужен и не требуется).
const ownBuildStampWordFile = "internal/observability/metrics/build_info.go"

// ownBuildStampWordConst — имя константы в том объявлении.
const ownBuildStampWordConst = "BuildInfoUnstamped"

// TestBuildStampWordMatchesThePlatformWord — слово одно на оба модуля.
func TestBuildStampWordMatchesThePlatformWord(t *testing.T) {
	t.Parallel()
	moduleRoot, err := platformtree.ModuleRootFrom(wdOf(t))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}
	path := filepath.Join(moduleRoot, filepath.FromSlash(ownBuildStampWordFile))

	src, err := os.ReadFile(path) // #nosec G304 -- путь-константа своего дерева
	if err != nil {
		t.Fatalf("%s: %v — «ноль находок» здесь означало бы «ноль прочитанного»",
			ownBuildStampWordFile, err)
	}

	word, found, err := check.ConstStringValue(src, ownBuildStampWordConst)
	if err != nil {
		t.Fatalf("%s: %v", ownBuildStampWordFile, err)
	}
	if !found {
		t.Fatalf("%s: константа %s не объявлена — сверять нечего, и молчание гейта "+
			"ничего не утверждало бы. Переехала? Поправьте координату ЗДЕСЬ",
			ownBuildStampWordFile, ownBuildStampWordConst)
	}

	t.Logf("перепись: прочитано объявлений 2 — платформа %q · служба доступа %q",
		observability.BuildStampUnstamped, word)

	if word != observability.BuildStampUnstamped {
		t.Errorf("слово «штамп не проставлен» разошлось между модулями: платформа "+
			"говорит %q, служба доступа — %q. Дежурный сверяет витрины разных процессов "+
			"не пересчитывая, а два написания одного состояния дают две тревоги об одном "+
			"предмете — и одна из них однажды не будет написана. Модули разные, общей "+
			"константы у них быть не может (пин), поэтому согласие держит только этот гейт",
			observability.BuildStampUnstamped, word)
	}
}

// wdOf — рабочий каталог либо ОТКАЗ: не установлен — судить не о чем.
func wdOf(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	return dir
}
