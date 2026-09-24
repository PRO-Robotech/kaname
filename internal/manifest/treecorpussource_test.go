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
//
// # Мир пробы строит фикстура, а не место временного каталога
//
// git ищет репозиторий, поднимаясь от корня, поэтому «индекса нет» зависит не
// только от корня, но и от того, что лежит НАД ним. Временный каталог внутри
// чужого git-дерева (рабочая копия полосы, TMPDIR под корнем воркспейса) получал
// индекс ТОГО дерева, и вердикт пробы становился свойством окружения прогона
// (задача PRO-Robotech/kaname#384). Поэтому мир «репозитория нет» фикстура ставит
// потолком поиска ([noEnclosingRepository]), а мир «корень внутри постороннего
// репозитория» — строит сама ([foreignRepositoryAround]), и оба не зависят от
// того, где лежит TMPDIR.
package manifest

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
	"github.com/PRO-Robotech/corelib/treecorpus"
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
	noEnclosingRepository(t, root)

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

// noEnclosingRepository — ставит миру пробы «репозитория НЕТ» независимо от
// того, где лежит временный каталог прогона.
//
// Потолок поиска — родитель корня: сам корень git осматривает, выше не
// поднимается, и объемлющее дерево, в которое попал TMPDIR, индекса пробе не
// подсунет. Предпосылка проверяется, а не предполагается: назвал git
// репозиторий — условие не создано, и это отказ фикстуры, а не красное предмета.
func noEnclosingRepository(t *testing.T, root string) {
	t.Helper()
	ceiling := filepath.Dir(root)
	t.Setenv("GIT_CEILING_DIRECTORIES", ceiling)
	if out, err := gitenv.Command(root, "rev-parse", "--show-toplevel").Output(); err == nil {
		t.Fatalf("УСЛОВИЕ НЕ СОЗДАНО (не находка): git назвал репозиторий %q над %s при "+
			"потолке поиска %s — мир «репозитория нет» фикстурой не построен",
			strings.TrimSpace(string(out)), root, ceiling)
	}
}

// foreignRepositoryAround — ПОСТОРОННИЙ репозиторий с корнем обхода внутри:
// каталог `полоса/` лежит под ним, манифест в нём на диске всегда, в индексе —
// только при tracked.
//
// Свой файл посторонний репозиторий отслеживает всегда: иначе «корень им не
// отслеживается» совпало бы с «индекс пуст», и проба судила бы не тот мир.
// Ближайший `.git` над корнем — этого репозитория, поэтому мир не зависит от
// того, лежит ли TMPDIR в чужом дереве.
func foreignRepositoryAround(t *testing.T, tracked bool) (outer, root string) {
	t.Helper()
	const rel = "полоса/services/vpc/manifest.yaml"
	inIndex := map[string]string{"README.md": "посторонний репозиторий\n"}
	onDisk := map[string]string{}
	if tracked {
		inIndex[rel] = goodManifest(t)
	} else {
		onDisk[rel] = goodManifest(t)
	}
	outer = gitTree(t, inIndex, onDisk)
	return outer, filepath.Join(outer, "полоса")
}

// resolved — путь в том написании, в каком его печатает git (`rev-parse`
// разрешает символьные ссылки): находка называет репозиторий словами git.
func resolved(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("путь %s не разрешён: %v", p, err)
	}
	return r
}

// TestCheckTreeRefusesARootTheIndexDoesNotTrack — индекс, не знающий под корнем
// НИ ОДНОГО файла, даёт НАХОДКУ, называющую причину, а не «проверять нечего».
//
// git отвечает на перечисление пустотой в двух мирах: корень лежит внутри
// ПОСТОРОННЕГО репозитория и им не отслеживается — либо корень сам репозиторий,
// но в его индекс не заведено ничего. Ни в одном полоса дерева не прочитала
// состава коммита, и VOID объявил бы «манифеста нет ни одного» о корне, на диске
// которого манифест лежит (задача PRO-Robotech/kaname#384).
//
// У каждого отказа — законный близнец, отличающийся РОВНО ОДНИМ фактом: тот же
// мир, манифест заведён в индекс. Без близнецов отказ зеленел бы на полосе,
// отвергающей всякий корень.
func TestCheckTreeRefusesARootTheIndexDoesNotTrack(t *testing.T) {
	refuseCachedVerdict(t)

	t.Run("корень внутри постороннего репозитория, им не отслеживается", func(t *testing.T) {
		outer, root := foreignRepositoryAround(t, false)
		for lane, check := range map[string]func(string) CheckReport{
			"CheckTree":              func(r string) CheckReport { return CheckTree(r) },
			"CheckTreeForGeneration": CheckTreeForGeneration,
		} {
			report := check(root)
			t.Logf("%s: перепись отказа: %s", lane, report.Summary())
			if report.ExitCode() != CheckFailed {
				t.Fatalf("%s: корень, которого индекс не отслеживает, дал код %d, ожидалась "+
					"находка (%d): «проверять нечего» здесь ложь — манифест лежит на диске, а "+
					"полоса не прочитала ничего", lane, report.ExitCode(), CheckFailed)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("%s: находок %d, положена одна: %v", lane, len(report.Findings), report.Findings)
			}
			f := report.Findings[0]
			t.Logf("%s: находка: %s", lane, f)
			for _, want := range []string{resolved(t, outer), "полоса/", "не отслеживается"} {
				if !strings.Contains(f, want) {
					t.Errorf("%s: находка не называет причину — нет %q: %s", lane, want, f)
				}
			}
			if !strings.Contains(report.Summary(), "осмотрено файлов 0") {
				t.Errorf("%s: отчёт вернулся БЕЗ переписи: %q", lane, report.Summary())
			}
		}
	})

	t.Run("законный близнец: тот же корень отслеживается объемлющим репозиторием", func(t *testing.T) {
		_, root := foreignRepositoryAround(t, true)
		report := CheckTree(root)
		t.Logf("перепись близнеца: %s", report.Summary())
		if report.ExitCode() != CheckOK || report.ManifestsRead != 1 {
			t.Fatalf("корень-подкаталог, отслеживаемый объемлющим репозиторием (модуль "+
				"внутри монорепо), дал код %d и манифестов %d, ожидались %d и 1: отказ "+
				"отнял законную посадку; находки: %v",
				report.ExitCode(), report.ManifestsRead, CheckOK, report.Findings)
		}
	})

	t.Run("корень — репозиторий с пустым индексом", func(t *testing.T) {
		root := gitTree(t, nil, map[string]string{"services/vpc/manifest.yaml": goodManifest(t)})
		report := CheckTree(root)
		t.Logf("перепись отказа: %s", report.Summary())
		if report.ExitCode() != CheckFailed {
			t.Fatalf("репозиторий с пустым индексом дал код %d, ожидалась находка (%d)",
				report.ExitCode(), CheckFailed)
		}
		if len(report.Findings) != 1 || !strings.Contains(report.Findings[0], "индексе нет ни одного файла") {
			t.Fatalf("находка не называет причину «индекс пуст»: %v", report.Findings)
		}
		t.Logf("находка: %s", report.Findings[0])
	})

	t.Run("законный близнец: тот же репозиторий, манифест в индексе", func(t *testing.T) {
		root := gitTree(t, map[string]string{"services/vpc/manifest.yaml": goodManifest(t)}, nil)
		report := CheckTree(root)
		t.Logf("перепись близнеца: %s", report.Summary())
		if report.ExitCode() != CheckOK || report.ManifestsRead != 1 {
			t.Fatalf("репозиторий с манифестом в индексе дал код %d и манифестов %d, "+
				"ожидались %d и 1; находки: %v",
				report.ExitCode(), report.ManifestsRead, CheckOK, report.Findings)
		}
	})
}
