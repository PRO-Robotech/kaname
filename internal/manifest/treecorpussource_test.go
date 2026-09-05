// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// treecorpussource_test.go — перечень путей обхода берётся ПО НАЗНАЧЕНИЮ полосы:
// дерево разработки спрашивает ИНДЕКС git, каталог доставки — диск
// (задача PRO-Robotech/kacho#2041).
//
// # Предмет
//
// Под корнем репозитория лежат каталоги, которых в репозитории НЕТ: рабочие
// копии агентов, отчёты прогонов, локальные накладки, сборочные каталоги. Обход
// по диску делает вердикт свойством ЧУЖОГО рабочего каталога, а не коммита, — и
// ошибается в обе стороны: краснеет на файле, которого в репозитории нет, и
// молчит в свежем клоне там, где сказать обязан.
//
// # Почему двух проб мало, а трёх достаточно
//
// Утверждение «полоса дерева не видит неотслеживаемого» на дереве БЕЗ
// неотслеживаемого истинно тривиально. Поэтому мир у обеих проб ОДИН и тот же —
// один и тот же корень, в котором лежат оба манифеста, — а различается ровно
// ОДИН факт: у какой полосы спрашивают перечень. Третья проба держит громкость
// отказа: корень без индекса обязан дать находку вместе с переписью, а не
// успокоительное «проверять нечего».
package manifest

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// refuseCachedVerdict — вердикт, который `go test` положит в кеш, недействителен:
// состав дерева берётся подпроцессом, инструменту невидимым.
func refuseCachedVerdict(t *testing.T) {
	t.Helper()
	if msg := treecorpus.CachedVerdictRefusal(); msg != "" {
		t.Fatalf("%s — «ноль находок» стало бы свойством рабочего каталога", msg)
	}
}

// gitTree — синтетический РЕПОЗИТОРИЙ: часть файлов заведена в индекс, часть
// лежит только на диске. Именно это различие и есть предмет проб файла.
func gitTree(t *testing.T, tracked, untracked map[string]string) string {
	t.Helper()
	all := make(map[string]string, len(tracked)+len(untracked))
	for rel, body := range tracked {
		all[rel] = body
	}
	for rel, body := range untracked {
		all[rel] = body
	}
	root := writeTree(t, all)
	git := func(args ...string) {
		t.Helper()
		// gitenv, а не exec напрямую: `cmd.Dir` НЕ выбирает репозиторий, когда в
		// окружении стоит GIT_DIR — переменная сильнее рабочего каталога, и
		// фикстура писала бы индекс ТОЙ копии, из которой запущен прогон.
		cmd := gitenv.Command(root, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v в %s: %v\n%s", args, root, err, out)
		}
	}
	git("init", "-q")
	for rel := range tracked {
		git("add", "--", rel)
	}
	return root
}

// twoManifests — два годных манифеста разных модулей: один отслеживаемый, второй
// только на диске.
func twoManifests(t *testing.T) (tracked, untracked map[string]string) {
	t.Helper()
	good := goodManifest(t)
	return map[string]string{
			"services/vpc/manifest.yaml": good,
		}, map[string]string{
			"отчёт-прогона/manifest.yaml": strings.Replace(good, "module: vpc", "module: compute", 1),
		}
}

// TestCheckTreeTakesItsCorpusFromTheIndexNotTheDisk — полоса ДЕРЕВА читает
// только то, что лежит в индексе.
func TestCheckTreeTakesItsCorpusFromTheIndexNotTheDisk(t *testing.T) {
	refuseCachedVerdict(t)
	tracked, untracked := twoManifests(t)
	root := gitTree(t, tracked, untracked)

	report := CheckTree(root)
	t.Logf("перепись полосы дерева: %s", report.Summary())

	if report.ManifestsRead != 1 {
		t.Fatalf("полоса дерева прочитала манифестов %d, положено 1: неотслеживаемый "+
			"манифест прочитан, и вердикт стал свойством рабочего каталога, а не коммита; "+
			"прочитаны %v", report.ManifestsRead, report.Paths)
	}
	for _, p := range report.Paths {
		if strings.Contains(p, "отчёт-прогона") {
			t.Errorf("полоса дерева прочитала неотслеживаемый путь %s", p)
		}
	}
}

// TestDeliveryLaneStillReadsTheDisk — ЗАКОННЫЙ БЛИЗНЕЦ: полоса доставки на том
// же корне читает ОБА манифеста.
//
// Без него отрицание выше зеленело бы на полосе, которая не читает ничего.
func TestDeliveryLaneStillReadsTheDisk(t *testing.T) {
	refuseCachedVerdict(t)
	tracked, untracked := twoManifests(t)
	root := gitTree(t, tracked, untracked)

	report := CheckDelivery(root)
	t.Logf("перепись полосы доставки: %s", report.Summary())

	if report.ManifestsRead != 2 {
		t.Fatalf("полоса доставки прочитала манифестов %d, положено 2: индекса у "+
			"каталога доставки нет by construction, и диск здесь единственный "+
			"авторитет; прочитаны %v", report.ManifestsRead, report.Paths)
	}
}

// TestCheckTreeRefusesLoudlyWhenTheRootHasNoIndex — корень без индекса даёт
// НАХОДКУ вместе с переписью, а не успокоительное «проверять нечего».
//
// Клауза уронила прежнюю попытку правки: отчёт возвращался без переписи, и «ноль
// находок» становилось неотличимо от «ноль прочитанного» ровно там, где полоса
// обязана кричать.
func TestCheckTreeRefusesLoudlyWhenTheRootHasNoIndex(t *testing.T) {
	refuseCachedVerdict(t)
	root := writeTree(t, map[string]string{"services/vpc/manifest.yaml": goodManifest(t)})

	report := CheckTree(root)
	t.Logf("перепись отказа: %s", report.Summary())

	if report.ExitCode() != CheckFailed {
		t.Fatalf("корень без индекса дал код %d, ожидалась находка (%d): непрочитанное "+
			"есть НАХОДКА, а не «проверять нечего»", report.ExitCode(), CheckFailed)
	}
	if !strings.Contains(report.Summary(), "осмотрено файлов") {
		t.Errorf("отчёт вернулся БЕЗ переписи: %q", report.Summary())
	}
}
