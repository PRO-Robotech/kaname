// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_kind_sender_parity_test.go — у КАЖДОГО вида письма ровно ОДИН
// отправитель (приёмка `docs/engineering/acceptance/recovery-of-access.md`,
// Р3; сценарии Ф5-10 «перепись видов и отправителей печатает ДВЕ величины» и
// Ф5-11 «законный близнец молчит»; задача PRO-Robotech/kacho#1271).
//
// # Предмет
//
// Словарь видов письма закреплён ограничением схемы на очереди писем, а
// принимает вид к отправке применитель дренажа — код, который на вид
// ВЕТВИТСЯ. Два объявления об одном предмете расходятся молча: вид, добавленный
// в схему и не принятый ни одним применителем, ложится в очередь и там
// отравляется как «неизвестный»; ветвь применителя на вид, которого схема не
// допускает, не исполняется никогда. Оба состояния зелены для всякой пробы,
// которая смотрит на одну сторону.
//
// ID-MAIL-1 Р23 называет признак дословно: вид письма, у которого два
// отправителя, — либо вид письма, у которого нет ни одного. Гейт судит ОБЕ
// стороны и печатает ОБЕ величины: одно число «видов N» скрыло бы ровно тот
// случай, ради которого сверка заведена.
//
// # Что читается
//
// Схема — по корпусу миграций: последнее живое объявление ограничения на
// колонку вида события с непустым перечнем видов пространства `mail.`.
// Отправитель — по прод-корпусу Go: функции формы применителя дренажа
// (`func(ctx, eventType string, payload T) error`) и то, с чем они сравнивают
// свой параметр вида. Обе стороны — узлы разбора, не подстроки: проза о видах
// письма несёт те же слова и на вердикт влиять не вправе.
package check_test

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// mailKindCensus — строка переписи, общая пробам семейства. Две величины
// приёмки печатаются ПЕРВЫМИ и порознь.
func mailKindCensus(inv check.MailKindInventory) string {
	return "перепись: " + strings.Join([]string{
		"видов письма " + strconv.Itoa(len(inv.Kinds)),
		"из них с отправителем " + strconv.Itoa(inv.KindsWithSender()),
		"применителей " + strconv.Itoa(inv.Appliers),
		"миграций осмотрено " + strconv.Itoa(inv.MigrationsRead),
		"объявлений словаря видов " + strconv.Itoa(inv.VocabularyDeclarations),
		"прод-файлов Go " + strconv.Itoa(inv.GoFilesRead),
		"сравнений вида осмотрено " + strconv.Itoa(inv.ComparisonSites),
	}, " · ")
}

// TestEveryMailKindHasExactlyOneSender — сам гейт (Ф5-10).
//
// Три исхода, и третий назван отдельно: перепись не собрана — «проверка НЕ
// ИСПОЛНЯЛАСЬ», не зелёное и не красное.
func TestEveryMailKindHasExactlyOneSender(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог: %v", err)
	}
	root, rerr := platformtree.ModuleRootFrom(wd)
	if rerr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля: %v", rerr)
	}
	tree := gateTree(t, root)

	migrations, merr := check.MigrationCorpus(tree.tree)
	if merr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корпус миграций не собран: %v", merr)
	}
	corpus, cerr := check.DrainSiteCorpus(tree.tree)
	if cerr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: прод-корпус Go не собран: %v", cerr)
	}

	inv, ierr := check.MailKindInventoryOf(migrations, corpus)
	if ierr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: перепись видов письма не собрана: %v", ierr)
	}
	t.Log(mailKindCensus(inv))

	// Предпосылки гейта — ЗАЯВЛЯЮТСЯ, а не подразумеваются: словарь видов и
	// хотя бы один применитель обязаны быть прочитаны, иначе «находок ноль»
	// означало бы «прочитано ноль». Сборщик отказывает на них сам
	// (ErrEmptyTraversal); здесь они повторены вслух, чтобы читатель вердикта
	// видел, на чём он стоит.
	if len(inv.Kinds) == 0 || inv.Appliers == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: словарь видов пуст (%d) либо применителей "+
			"не найдено (%d) — судить нечего", len(inv.Kinds), inv.Appliers)
	}

	for _, f := range inv.Findings() {
		t.Errorf("%s", f)
	}
}

// TestEveryMailKindHasExactlyOneSender_TwoNumbersAreDistinct — форма переписи
// (Р3): величины две, и они РАЗНЫЕ утверждения. «Видов N» считает схему,
// «с отправителем M» считает применителей; на исправном дереве они равны, и
// равенство здесь — вердикт, а не совпадение формы записи.
func TestEveryMailKindHasExactlyOneSender_TwoNumbersAreDistinct(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог: %v", err)
	}
	root, rerr := platformtree.ModuleRootFrom(wd)
	if rerr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля: %v", rerr)
	}
	tree := gateTree(t, root)
	migrations, merr := check.MigrationCorpus(tree.tree)
	if merr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корпус миграций не собран: %v", merr)
	}
	corpus, cerr := check.DrainSiteCorpus(tree.tree)
	if cerr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: прод-корпус Go не собран: %v", cerr)
	}
	inv, ierr := check.MailKindInventoryOf(migrations, corpus)
	if ierr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: перепись видов письма не собрана: %v", ierr)
	}

	kinds := append([]string(nil), inv.Kinds...)
	sort.Strings(kinds)
	if !sort.StringsAreSorted(inv.Kinds) {
		t.Errorf("перечень видов обязан быть детерминированным (отсортированным), "+
			"иначе два прогона несравнимы: %v", inv.Kinds)
	}
	if got, want := inv.KindsWithSender(), len(inv.Kinds); got != want {
		t.Errorf("видов письма %d, с отправителем %d — числа расходятся, и это "+
			"находка, а не форма записи: %v", want, got, inv.Findings())
	}
	if !strings.HasPrefix(inv.Kinds[0], check.MailKindNamespace) {
		t.Errorf("вид %q не в пространстве %q — сборщик прочитал не тот словарь",
			inv.Kinds[0], check.MailKindNamespace)
	}
}
