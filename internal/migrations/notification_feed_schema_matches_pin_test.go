// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notification_feed_schema_matches_pin_test.go — схема ленты уведомлений в
// дереве миграций kaname совпадает с версией схемы пина corelib (kaname#484,
// возврат PR #628, находки B1 и C1).
//
// # Предмет
//
// Постановку в ленту пишет библиотека пина (`notify/feed`, put.go): её
// оператор вставки называет колонки схемы версии `schema.Current()` пина.
// Схему таблицы задают миграции дерева, порождённые `notifygen init`. Перепин
// corelib на библиотеку новой версии схемы БЕЗ `notifygen init` оставляет
// таблицу на прежней версии: каждый вызов `feedgen.Send*` падает в базе
// (колонки нет) и откатывает всю мутацию вызывающего, а словарь состояний
// отвергает состояния новой версии. `notifygen -check` такое дерево не
// судит: он сверяет каждый файл ленты с выпущенным содержимым его версии, а
// не то, что старшая версия дерева равна версии пина.
//
// Судья — сам генератор версии пина: `notifygen init` над КОПИЕЙ каталога
// миграций печатает «изменений 0», когда старшая версия ленты дерева равна
// `schema.Current()` пина, и пишет миграцию подъёма («изменений 1»), когда
// она ниже. Своего разбора имён миграций и номера версии проба не заводит:
// генератор и есть то, что порождает файл, который здесь требуется.
//
// # Порядок проверок несущий
//
// Сперва фикстура — генератор пина исполняется и на синтетическом каталоге,
// несущем ТОЛЬКО первую миграцию ленты дерева, пишет подъём (законная
// отрицательная форма: версия ниже пина). Затем близнец на копии дерева как
// есть — «изменений 0». Неисполнившийся генератор не выдаёт себя за зелёный.
package migrations_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// feedNotifygenPkg — генератор версии пина corelib из go.mod дерева.
const feedNotifygenPkg = "github.com/PRO-Robotech/corelib/cmd/notifygen"

// feedService — префикс таблиц ленты kaname (служба `kaname`, схема `kaname`).
const feedService = "kaname.kaname"

// feedMigrationsDir — каталог миграций kaname от корня дерева.
const feedMigrationsDir = "internal/migrations"

// feedMigrationName — имя миграции ленты, которое пишет `notifygen init`;
// служит только переписи осмотренного, вердикт выносит генератор.
var feedMigrationName = regexp.MustCompile(`^[0-9]+_notification_feed_v[0-9]+(?:_from_v[0-9]+)?\.sql$`)

// feedInitResult — исход одного вызова `notifygen init`.
type feedInitResult struct {
	code           int
	stdout, stderr string
}

// feedTreeRoot — корень дерева kaname либо отказ прогона.
func feedTreeRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, _, err := treeposture.CorpusRoot(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень дерева не установлен: %v", err)
	}
	return root
}

// feedInit исполняет `notifygen init` версии пина (из корня дерева kaname)
// над корнем root. Генератор, не запустившийся, — отказ прогона, а не исход.
func feedInit(t *testing.T, kaname, root string) feedInitResult {
	t.Helper()
	args := []string{"run", feedNotifygenPkg, "-root", root, "init", "-service", feedService, "-migrations", feedMigrationsDir}
	cmd := exec.Command("go", args...) // #nosec G204 -- argv собран пробой
	cmd.Dir = kaname
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return feedInitResult{code: 0, stdout: so.String(), stderr: se.String()}
	case errors.As(err, &ee):
		if strings.Contains(se.String(), "exit status 2") {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: notifygen init — неверный вызов:\n%s", se.String())
		}
		return feedInitResult{code: ee.ExitCode(), stdout: so.String(), stderr: se.String()}
	}
	t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: notifygen init не запустился: %v\n%s", err, se.String())
	return feedInitResult{}
}

// copyMigrations копирует перечисленные файлы каталога миграций дерева в
// <dst>/internal/migrations и возвращает dst.
func copyMigrations(t *testing.T, kaname string, names []string) string {
	t.Helper()
	dst := t.TempDir()
	to := filepath.Join(dst, filepath.FromSlash(feedMigrationsDir))
	if err := os.MkdirAll(to, 0o750); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	from := filepath.Join(kaname, filepath.FromSlash(feedMigrationsDir))
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(from, n)) // #nosec G304 -- имя из каталога миграций дерева
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		if err := os.WriteFile(filepath.Join(to, n), b, 0o600); err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
	}
	return dst
}

// treeMigrations — все файлы .sql каталога миграций дерева и среди них
// миграции ленты (по возрастанию имени).
func treeMigrations(t *testing.T, kaname string) (all, feed []string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(kaname, filepath.FromSlash(feedMigrationsDir)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		all = append(all, e.Name())
		if feedMigrationName.MatchString(e.Name()) {
			feed = append(feed, e.Name())
		}
	}
	sort.Strings(all)
	sort.Strings(feed)
	return all, feed
}

// TestNotificationFeedSchemaMatchesThePinnedLibrary — старшая версия схемы
// ленты в дереве миграций равна `schema.Current()` пина corelib: `notifygen
// init` версии пина над копией каталога печатает «изменений 0».
func TestNotificationFeedSchemaMatchesThePinnedLibrary(t *testing.T) {
	kaname := feedTreeRoot(t)
	all, feed := treeMigrations(t, kaname)
	t.Logf("перепись: миграций %d · из них ленты %d: %v", len(all), len(feed), feed)
	if len(feed) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в %s нет ни одной миграции ленты — судить нечего (миграций всего %d)", feedMigrationsDir, len(all))
	}

	// Фикстура: каталог только с первой миграцией ленты дерева — генератор
	// пина обязан различить версию ниже своей и написать подъём.
	first := copyMigrations(t, kaname, feed[:1])
	if r := feedInit(t, kaname, first); r.code != 0 || !strings.Contains(r.stdout, "изменений 1") || !strings.Contains(r.stdout, "_from_v") {
		if r.code == 0 && strings.Contains(r.stdout, "изменений 0") && len(feed) == 1 {
			// Первая миграция ленты дерева уже версии пина: отрицательной
			// формы из дерева не собрать, близнец ниже судит один.
			t.Logf("фикстура: первая миграция ленты %s уже версии пина", feed[0])
		} else {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: генератор пина над каталогом из одной %s не написал подъём: код %d\nstdout:\n%s\nstderr:\n%s", feed[0], r.code, r.stdout, r.stderr)
		}
	}

	// Близнец: копия каталога дерева как есть.
	tree := copyMigrations(t, kaname, all)
	r := feedInit(t, kaname, tree)
	if r.code != 0 {
		t.Fatalf("notifygen init над копией %s: код %d\nstdout:\n%s\nstderr:\n%s", feedMigrationsDir, r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "изменений 0") {
		t.Fatalf("схема ленты дерева ниже версии пина corelib: notifygen init пишет подъём — миграция ленты не закоммичена вместе с перепином (без неё каждая постановка feedgen.Send* падает в базе):\n%s\nпочинка: `go run %s init -service %s -migrations %s` и коммит порождённого файла без правки",
			strings.TrimSpace(r.stdout), feedNotifygenPkg, feedService, feedMigrationsDir)
	}
	t.Logf("генератор пина: %s", strings.TrimSpace(r.stdout))
}
