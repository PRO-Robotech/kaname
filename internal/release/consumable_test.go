// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// consumable_test.go — модуль службы обязан СОБИРАТЬСЯ у постороннего.
//
// # Почему у этого утверждения свой держатель, а не чужой
//
// Рядом, в модуле платформы, живёт прогон с похожим именем. Он упаковывает и
// собирает ФУНДАМЕНТ, и о модуле службы не утверждает ничего: имена похожи,
// предметы разные. Расширять его на службу нельзя — у неё свой модуль, своё
// объявление зависимостей и свой владелец после разреза; после выноса продукта
// тот прогон уедет вместе с деревом, которое службе принадлежать перестанет.
//
// # Что именно проверяется
//
// Ревизия упаковывается `zip.CreateFromVCS` — той самой функцией, которой
// модуль-прокси формирует зип версии, — распаковывается ВНЕ всякого дерева и
// собирается там целиком. Ни рабочего пространства, ни соседних каталогов, ни
// подмены пути: зависимость на фундамент резолвится ПИНОМ, как у постороннего.
//
// # Что проба НЕ утверждает
//
// Она не утверждает, что версия ОПУБЛИКОВАНА, и не судит РАЗРЕШИМОСТЬ пина
// фундамента — у неё свой держатель и своя задача. Недостижимость прокси
// модулей здесь не красное, а третья категория: «условие не создано» не
// вычитается из вердикта и не зачитывается в успех.
//
// # Способность упасть
//
// Доказана `consumable_injection_test.go`: тот же код, применённый к
// синтетическому репозиторию с ОДНИМ изменённым фактом, обязан краснеть, а к
// его законному близнецу — молчать.
package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// TestExternalConsumerCanBuildTheServiceModule — предмет полосы выпуска
// службы отдельным продуктом.
func TestExternalConsumerCanBuildTheServiceModule(t *testing.T) {
	modRoot := moduleRoot(t)
	modPath := modulePathOf(t, modRoot)

	// Каталог модуля ВНУТРИ репозитория выводится, а не выписывается: в монорепо
	// это подкаталог, в самостоятельном клоне — корень. Литерал был бы верен
	// ровно для одной посадки и молча резолвился бы в чужой каталог в другой.
	repoRoot := repositoryRootOf(t, modRoot)
	subdir := subdirOf(t, repoRoot, modRoot)

	vcs := clonedForPacking(t, repoRoot)

	res := packAndBuildStandalone(t, packRequest{
		vcsRoot:    vcs,
		subdir:     subdir,
		modulePath: modPath,
	})

	t.Logf("перепись: модуль %s, каталог в дереве %q, ревизия %s, файлов упаковано %d, "+
		"пакетов собрано %d, зип %.1f МиБ, предел прокси %d МиБ",
		modPath, subdirLabel(subdir), short(res.revision), res.filesInZip, res.packages,
		float64(res.zipBytes)/(1<<20), maxZipMiB)

	// ПРЕДПОСЫЛКА. Пустой обход неотличим от чистого дерева, поэтому он отказ, а
	// не тихий успех.
	if res.filesInZip == 0 {
		t.Fatalf("обход пуст: в зипе НОЛЬ файлов — вердикт беспредметен.\n"+
			"Каталог модуля в дереве назван как %q; если он переехал, упаковано "+
			"будет ничто, и зелёное здесь означало бы «ничего не спросили»", subdirLabel(subdir))
	}

	// ТРЕТЬЯ КАТЕГОРИЯ — до вердикта, а не после: вердикта нет ВОВСЕ.
	if res.unmet != "" {
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): %s.\n"+
			"Вердикта о собираемости модуля %s НЕТ: упаковано файлов %d, но граф "+
			"зависимостей не разрешён. Это не красное и в успех не зачитывается.\n%s",
			res.unmet, modPath, res.filesInZip, res.output)
	}

	if res.err != nil {
		t.Fatalf("посторонний НЕ СОБИРАЕТ модуль %s из упакованной ревизии %s: %v\n"+
			"Упаковано файлов %d. Дерево собиралось на месте — значит сборке помогало "+
			"то, чего у постороннего нет: неотслеживаемый файл, объемлющее рабочее "+
			"пространство, подмена пути либо импорт каталога, наружу не выпускаемого.\n%s",
			modPath, short(res.revision), res.err, res.filesInZip, res.output)
	}

	// ВТОРАЯ ПОЛОВИНА ПЕРЕПИСИ. Зелёная сборка НУЛЯ пакетов — тот же пустой
	// обход, только с другой стороны.
	if res.packages == 0 {
		t.Fatalf("собрано НОЛЬ пакетов при %d упакованных файлах — вердикт беспредметен:\n%s",
			res.filesInZip, res.output)
	}
}

// repositoryRootOf — корень репозитория, которому принадлежит каталог модуля.
func repositoryRootOf(t *testing.T, dir string) string {
	t.Helper()
	cmd := gitenv.Command(dir, "rev-parse", "--show-toplevel")
	cmd.Env = cleanGitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Дерева истории нет — распакованный архив, а не клон. Вердикта об
		// упаковке из системы контроля версий здесь быть не может by
		// construction, и красное у всякого, кто развернул поставку, вердиктом
		// о продукте не является.
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): %s не лежит в репозитории (%v) — "+
			"упаковывать из системы контроля версий нечего.\n%s", dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// subdirOf — путь модуля внутри репозитория, в форме, которую ждёт упаковщик.
func subdirOf(t *testing.T, repoRoot, modRoot string) string {
	t.Helper()
	repoRoot = resolved(t, repoRoot)
	modRoot = resolved(t, modRoot)
	rel, err := filepath.Rel(repoRoot, modRoot)
	if err != nil {
		t.Fatalf("путь модуля в дереве не выведен (%s в %s): %v", modRoot, repoRoot, err)
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return "" // модуль в корне репозитория — так это выглядит у постороннего
	}
	if strings.HasPrefix(rel, "../") {
		t.Fatalf("каталог модуля %s лежит ВНЕ репозитория %s — упаковка была бы о чужом дереве",
			modRoot, repoRoot)
	}
	return rel
}

// clonedForPacking — каталог, годный для упаковки из системы контроля версий.
//
// Упаковщик опознаёт репозиторий по КАТАЛОГУ `.git`. В связанной рабочей копии
// (`git worktree`) `.git` — файл, и упаковщик отвечает «системы контроля версий
// не найдено». Полосы работают именно в связанных копиях, поэтому ветвление
// здесь не редкость, а обычный путь.
//
// Клонируется ВСЕГДА, а не только в связанной копии: ветвь, исполняемая лишь на
// машине полосы, в конвейере не проверяется ни разу и ломается незаметно.
func clonedForPacking(t *testing.T, repoRoot string) string {
	t.Helper()
	dst := filepath.Join(outsideAnyRepository(t), "vcs")
	cmd := gitenv.Command(filepath.Dir(dst), "clone", "--quiet", "--depth", "1", "--no-tags",
		"--single-branch", "file://"+repoRoot, dst)
	cmd.Env = cleanGitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		// УСЛОВИЕ НЕ СОЗДАНО, а не находка о модуле. Различие названо в самом
		// тексте: читатель, увидевший красное, обязан сразу понять, что вердикта
		// об упаковке НЕТ ВОВСЕ, и не искать поломку в своей ветке.
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): клон дерева %s не сделан (%v) — "+
			"вердикта об упаковке нет вовсе, это не находка о модуле\n%s", repoRoot, err, out)
	}
	return dst
}

func resolved(t *testing.T, dir string) string {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("абсолютный путь %s: %v", dir, err)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("каталог %s не читается: %v", abs, err)
	}
	return abs
}

func subdirLabel(subdir string) string {
	if subdir == "" {
		return "<корень репозитория>"
	}
	return subdir
}

func short(rev string) string {
	if len(rev) < 12 {
		return rev
	}
	return rev[:12]
}
