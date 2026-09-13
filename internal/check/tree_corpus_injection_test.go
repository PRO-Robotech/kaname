// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// tree_corpus_injection_test.go — доказательство, что отказ на пустом обходе
// СПОСОБЕН сработать и СПОСОБЕН смолчать (задача #17).
//
// Ради этого дерево и стало параметром. Прежде премиса пустого обхода стояла в
// теле каждой пробы, корнем ей служил корень своего модуля, и подать ей пустое
// дерево было НЕЧЕМ: ветвь отказа читалась глазами и не исполнялась ни разу.
//
// Каждая ось меняет РОВНО ОДИН факт против своего близнеца.
package check_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// synthTree — синтетическое дерево из перечня «путь → тело».
//
// Дерево строится `SyntheticTree`, а не `NewTree`: временный каталог
// репозиторием не является, индекса у него нет вовсе, и спрашивать его было бы
// вопросом к тому, чего фикстура не заводит. Конструктор выбран здесь ЯВНО —
// молчаливый откат «нет git, иду по диску» внутри общего конструктора вернул бы
// на боевом прогоне чтение игнорируемых каталогов.
func synthTree(t *testing.T, files map[string]string) *treecorpus.Tree {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
	}
	tree, err := treecorpus.SyntheticTree(root)
	if err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	return tree
}

// wantMD — отбор, одинаковый во всех осях ниже: различие обязано быть в ДЕРЕВЕ.
func wantMD(rel string) bool { return strings.HasSuffix(rel, ".md") }

// TestCorpusFrom_EmptyTraversalIsRefusedAndNonEmptyIsJudged — обе способности.
func TestCorpusFrom_EmptyTraversalIsRefusedAndNonEmptyIsJudged(t *testing.T) {
	t.Parallel()

	// ── КОНТРОЛЬ: отобранное есть — корпус выдан, отказа нет ────────────────
	//
	// Стоит первым и не формальность: без него всякий отказ ниже объяснялся бы
	// помощником, который отказывает на любом входе.
	corpus, err := check.CorpusFrom(synthTree(t, map[string]string{
		"docs/INSTALL.md": "тело",
		"internal/a.go":   "package a",
	}), wantMD)
	if err != nil {
		t.Fatalf("КОНТРОЛЬ: на дереве с отобранным файлом обход объявлен пустым: %v — "+
			"помощник отказывает на исправном входе, и ни одна ось ниже ничего не доказывает", err)
	}
	if got := corpus.Rels(); len(got) != 1 || got[0] != "docs/INSTALL.md" {
		t.Fatalf("КОНТРОЛЬ: отобрано %v, ожидался ровно docs/INSTALL.md — отбор берёт не то, "+
			"и «пусто» ниже значило бы «отбор сломан», а не «дерево пусто»", got)
	}
	if corpus["docs/INSTALL.md"] != "тело" {
		t.Fatalf("КОНТРОЛЬ: тело файла не прочитано — гейт судил бы пустую строку")
	}

	// ── ОСЬ 1: дерево ПУСТО — отказ, а не «находок ноль» ────────────────────
	//
	// Ровно та ветвь, которая до задачи #17 не исполнялась ни разу.
	_, err = check.CorpusFrom(synthTree(t, nil), wantMD)
	if err == nil {
		t.Fatal("пустое дерево прочиталось без отказа — «ноль находок» стало бы " +
			"неотличимо от «ноль прочитанного», и молчание гейта ничего бы не значило")
	}
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Errorf("отказ не опознаётся как пустой обход (%v) — вызывающий не отличит его "+
			"от «читать не удалось», а чинятся они по-разному", err)
	}

	// ── ОСЬ 2: дерево НЕПУСТО, но отобрано ноль — тот же отказ ──────────────
	//
	// Отличается от оси 1 ровно одним фактом: файлы есть. Без неё помощник
	// зеленел бы на дереве, которое он ЧИТАЛ и в котором не нашёл предмета, —
	// то есть на самом частом виде слепоты: предмет переехал, отбор остался.
	_, err = check.CorpusFrom(synthTree(t, map[string]string{
		"internal/a.go": "package a",
	}), wantMD)
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("дерево без отобранного не объявлено пустым обходом: %v — предмет, "+
			"переехавший из-под отбора, прошёл бы как «находок нет»", err)
	}
	if !strings.Contains(err.Error(), "осмотрено файлов дерева 1") {
		t.Errorf("отказ не назвал ОБЪЁМ осмотренного (%v) — «отбор не нашёл» и «дерева "+
			"не прочитано» остались бы неразличимы", err)
	}

	// ── ОСЬ 3: файл не прочитан — отказ ДРУГОЙ ──────────────────────────────
	//
	// Слив его с пустым обходом, помощник посылал бы читателя чинить предмет
	// гейта там, где сломаны условия прогона.
	tree := synthTree(t, map[string]string{"docs/INSTALL.md": "тело"})
	if err := os.Remove(filepath.Join(tree.Root(), "docs", "INSTALL.md")); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	_, err = check.CorpusFrom(tree, wantMD)
	if err == nil {
		t.Fatal("непрочитанный файл не дал отказа — гейт судил бы файл, которого не читал")
	}
	if errors.Is(err, check.ErrEmptyTraversal) {
		t.Errorf("«не прочитан» выдан за «обход пуст» (%v) — диагностика назовёт ложную "+
			"причину, и починку будут искать не там", err)
	}
	if !strings.Contains(err.Error(), "docs/INSTALL.md") {
		t.Errorf("отказ не называет координату: %v", err)
	}

	t.Log("осей 4: контроль · пустое дерево · непустое дерево без отобранного · " +
		"нечитаемый файл — отказы двух разных видов, проход один")
}
