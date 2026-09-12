// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// consumable_injection_test.go — доказательство падучести держателя годности.
//
// # Зачем отдельная проба
//
// `TestExternalConsumerCanBuildTheServiceModule` зелен на исправном дереве, и
// на исправном дереве зелен ТАКЖЕ держатель, потерявший способность краснеть.
// Отличить их нельзя ничем, кроме внесённого дефекта.
//
// # Почему дефект вносится в СИНТЕТИЧЕСКИЙ репозиторий
//
// Внести его в наше дерево значило бы сломать сборку всем остальным пробам:
// красное пришло бы от соседа, и новый держатель мог бы оказаться вакуумным,
// не показав этого ничем. Синтетика изолирует предмет, а гоняется по ней ТОТ ЖЕ
// `packAndBuildStandalone`, что и по нашему дереву.
//
// # Синтетика повторяет ФОРМУ предмета, а не его размер
//
// Один репозиторий, два модуля: в корне — зависимость (роль фундамента), в
// подкаталоге — модуль, который собирает посторонний (роль службы). Второй
// объявляет первый ВЕРСИЕЙ, и версия эта берётся из файлового прокси. Значит
// полоса «зависимость резолвится пином» проходится по-настоящему, и при этом
// без единого обращения в сеть.
//
// # Одно-фактность
//
// У каждого дефекта есть ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся ровно одним названным
// фактом. Без близнеца красное ничего не доказывает: покраснеть мог сосед.
package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
)

const (
	syntheticDepPath = "example.com/dependency"
	syntheticSvcPath = "example.com/service"
	syntheticSubdir  = "svc"
	syntheticDepVer  = "v0.0.1"
	syntheticSelfVer = "v0.0.0-20000101000000-000000000000"
)

// synthetic — описание синтетического репозитория. Поля меняются по ОДНОМУ:
// именно это делает красное доказательством, а не совпадением.
type synthetic struct {
	importSealedDir bool // импортировать каталог, который наружу не выпускается
	untrackHelper   bool // оставить нужный сборке файл вне индекса git
	replaceByPath   bool // подменить зависимость локальным путём вместо пина
}

// buildSynthetic — репозиторий из двух модулей.
func buildSynthetic(t *testing.T, s synthetic) string {
	t.Helper()
	dir := filepath.Join(outsideAnyRepository(t), "repo")
	for _, sub := range []string{"pkg/lib", "internal/inner", syntheticSubdir} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(sub)), 0o755); err != nil {
			t.Fatalf("каталог не создан: %v", err)
		}
	}

	// Модуль-зависимость: одна выпускаемая наружу функция и одна, лежащая в
	// каталоге, который правила модуля наружу не выпускают.
	write(t, filepath.Join(dir, "go.mod"), "module "+syntheticDepPath+"\n\ngo 1.21\n")
	write(t, filepath.Join(dir, "pkg", "lib", "lib.go"),
		"package lib\n\nfunc Answer() int { return 42 }\n")
	write(t, filepath.Join(dir, "internal", "inner", "inner.go"),
		"package inner\n\nfunc Hidden() int { return 7 }\n")

	// Модуль, который собирает посторонний.
	svc := filepath.Join(dir, syntheticSubdir)
	gomod := "module " + syntheticSvcPath + "\n\ngo 1.21\n\nrequire " +
		syntheticDepPath + " " + syntheticDepVer + "\n"
	if s.replaceByPath {
		// РОВНО ОДИН факт: зависимость берётся ПУТЁМ, а не пином. У нас путь
		// резолвится, у постороннего каталога рядом нет вовсе.
		gomod += "\nreplace " + syntheticDepPath + " => ../\n"
	}
	write(t, filepath.Join(svc, "go.mod"), gomod)

	imported := syntheticDepPath + "/pkg/lib"
	if s.importSealedDir {
		// РОВНО ОДИН факт: импортируется каталог, наружу не выпускаемый.
		imported = syntheticDepPath + "/internal/inner"
	}
	call := "dep.Answer()"
	if s.importSealedDir {
		call = "dep.Hidden()"
	}
	main := "package main\n\nimport dep \"" + imported + "\"\n\nfunc main() { _ = " + call
	if s.untrackHelper {
		main += " + helper()"
	}
	main += " }\n"
	write(t, filepath.Join(svc, "main.go"), main)
	if s.untrackHelper {
		write(t, filepath.Join(svc, "helper.go"), "package main\n\nfunc helper() int { return 1 }\n")
	}

	env := append(gitenv.Env(),
		"GIT_AUTHOR_NAME=probe", "GIT_AUTHOR_EMAIL=probe@invalid",
		"GIT_COMMITTER_NAME=probe", "GIT_COMMITTER_EMAIL=probe@invalid")
	git := func(args ...string) {
		c := gitenv.Command(dir, args...)
		c.Env = env
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "--quiet", "-b", "main")
	if s.untrackHelper {
		// РОВНО ОДИН факт: помощник остаётся в рабочем дереве и не попадает в
		// индекс. Локально модуль собирается, у постороннего файла нет.
		git("add", "go.mod", "pkg", "internal", syntheticSubdir+"/go.mod", syntheticSubdir+"/main.go")
	} else {
		git("add", "-A")
	}
	git("commit", "--quiet", "-m", "synthetic")
	return dir
}

// packSynthetic — прогнать синтетику ТЕМ ЖЕ кодом, что и предмет.
func packSynthetic(t *testing.T, s synthetic) packResult {
	t.Helper()
	repo := buildSynthetic(t, s)
	work := outsideAnyRepository(t)
	proxy := filepath.Join(work, "proxy")

	// Зависимость публикуется в файловый прокси: пин обязан резолвиться так же,
	// как у постороннего, и при этом без сети.
	publishToProxy(t, proxy, packRequest{
		vcsRoot:    repo,
		subdir:     "",
		modulePath: syntheticDepPath,
	}, syntheticDepVer)

	return packAndBuildStandalone(t, packRequest{
		vcsRoot:    repo,
		subdir:     syntheticSubdir,
		modulePath: syntheticSvcPath,
		version:    syntheticSelfVer,
		proxyDir:   proxy,
		modcache:   filepath.Join(work, "modcache"),
	})
}

// TestServiceConsumabilityStaysSilentOnALegitimateTwin — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него отрицания ниже зеленели бы на чём угодно: механизм, отвергающий
// всякий вход, краснеет на дефекте так же исправно, как годный. Здесь же
// проходится и полоса пина: зависимость резолвится ВЕРСИЕЙ из прокси.
func TestServiceConsumabilityStaysSilentOnALegitimateTwin(t *testing.T) {
	res := packSynthetic(t, synthetic{})
	t.Logf("законный близнец: файлов упаковано %d, пакетов собрано %d, зип %d Б",
		res.filesInZip, res.packages, res.zipBytes)
	if res.unmet != "" {
		t.Fatalf("синтетика ходит в сеть, а не должна (%s):\n%s", res.unmet, res.output)
	}
	if res.err != nil {
		t.Fatalf("законный близнец обязан собираться, а не собрался: %v\n%s", res.err, res.output)
	}
	if res.filesInZip == 0 || res.packages == 0 {
		t.Fatalf("контроль беспредметен: упаковано %d файлов, собрано %d пакетов\n%s",
			res.filesInZip, res.packages, res.output)
	}
}

// TestServiceConsumabilityRedOnAnImportOutsideThePublishedModule — ось 1.
//
// Импорт каталога, который правила модуля наружу не выпускают: внутри своего
// дерева такой код собирается, у всякого другого потребителя — нет. Это и есть
// форма «импорт пути, которого во внешнем мире не существует».
func TestServiceConsumabilityRedOnAnImportOutsideThePublishedModule(t *testing.T) {
	res := packSynthetic(t, synthetic{importSealedDir: true})
	if res.unmet != "" {
		t.Fatalf("ожидалось красное, а получено «условие не создано» (%s):\n%s", res.unmet, res.output)
	}
	if res.err == nil {
		t.Fatalf("импорт наружу не выпускаемого каталога обязан ронять держателя, а он смолчал\n%s",
			res.output)
	}
	if !strings.Contains(res.output, syntheticDepPath+"/internal/inner") {
		t.Fatalf("находка не называет координату (ожидался путь %s/internal/inner):\n%s",
			syntheticDepPath, res.output)
	}
	t.Logf("ось 1 (импорт вне выпускаемого наружу): держатель краснеет и называет путь — %s",
		findingLine(res.output))
}

// TestServiceConsumabilityRedOnAnUntrackedSource — ось 2.
//
// Файл есть в рабочем дереве и нет в индексе. Локальная сборка о нём молчит,
// потому что читает диск; упаковывается отслеживаемое, и у постороннего файла
// нет вовсе. Ровно этот класс сборка дерева не видит.
func TestServiceConsumabilityRedOnAnUntrackedSource(t *testing.T) {
	res := packSynthetic(t, synthetic{untrackHelper: true})
	if res.unmet != "" {
		t.Fatalf("ожидалось красное, а получено «условие не создано» (%s):\n%s", res.unmet, res.output)
	}
	if res.err == nil {
		t.Fatalf("неотслеживаемый исходник обязан ронять держателя, а он смолчал\n%s", res.output)
	}
	if !strings.Contains(res.output, "helper") {
		t.Fatalf("находка не называет координату (ожидалось имя helper):\n%s", res.output)
	}
	t.Logf("ось 2 (файл не отслеживается): держатель краснеет — %s", findingLine(res.output))
}

// TestServiceConsumabilityRedOnAPathReplacement — ось 3.
//
// Зависимость подменена локальным путём вместо пина — то самое, что запрещено
// правилом полирепо-топологии. В дереве такая подмена резолвится, у постороннего
// каталога рядом нет.
func TestServiceConsumabilityRedOnAPathReplacement(t *testing.T) {
	res := packSynthetic(t, synthetic{replaceByPath: true})
	if res.unmet != "" {
		t.Fatalf("ожидалось красное, а получено «условие не создано» (%s):\n%s", res.unmet, res.output)
	}
	if res.err == nil {
		t.Fatalf("подмена зависимости путём обязана ронять держателя, а он смолчал\n%s", res.output)
	}
	if !strings.Contains(res.output, syntheticDepPath) {
		t.Fatalf("находка не называет подменённый модуль %s:\n%s", syntheticDepPath, res.output)
	}
	t.Logf("ось 3 (подмена пином на путь): держатель краснеет — %s", findingLine(res.output))
}

// findingLine — самая ЧАСТНАЯ строка вывода: последняя содержательная строка
// последней исполненной команды.
//
// Не первая строка всего вывода и не первая строка отказа: перед находкой идут
// шаги переписи, а сам отказ открывается заголовком пакета
// («package example.com/service»), в котором координаты нет. Находка, называющая
// не своё место, посылает читателя искать не там — на это в корпусе уже
// тратились прогоны.
func findingLine(s string) string {
	lines := strings.Split(s, "\n")
	start := 0
	for i, l := range lines {
		if strings.HasPrefix(l, "$ ") {
			start = i + 1
		}
	}
	out := ""
	for _, l := range lines[start:] {
		if t := strings.TrimSpace(l); t != "" {
			out = t
		}
	}
	return out
}

// --- Третья категория: у неё СВОЙ держатель ---------------------------------
//
// Ветвь «условие не создано» в предмете недостижима, пока кэш модулей тёпл, —
// а тёпл он почти всегда. Значит без отдельного утверждения эта ветвь есть
// объявление без исполнителя: она не краснеет и не зеленеет, она молчит.
//
// Вход НЕ ВЫДУМАН: три текста ниже сняты с инструмента настоящими прогонами
// (недостижимый прокси; поиск модулей отключён; прокси ответил «такой версии
// нет»). Выдуманная фикстура проверяла бы наше представление о выводе, а не
// вывод.
//
// Отрицательная сторона здесь несущая: третья категория, выданная лишнему
// случаю, — маска. Прокси, ОТВЕТИВШИЙ «нет такой версии», связь имеет; его
// предмет — разрешимость пина, и у неё свой держатель. Отказ сборки — тем
// более находка.
func TestUnmetReasonSeparatesAbsentNetworkFromAFinding(t *testing.T) {
	type probe struct {
		name  string
		out   string
		unmet bool
	}
	probes := []probe{
		{
			name: "прокси недостижим — транспорт",
			out: `go: example.com/nothing@v1.0.0: Get "http://127.0.0.1:1/mod/example.com/nothing/@v/v1.0.0.mod": ` +
				`dial tcp 127.0.0.1:1: connect: connection refused`,
			unmet: true,
		},
		{
			name:  "поиск модулей отключён настройкой",
			out:   "go: example.com/nothing@v1.0.0: module lookup disabled by GOPROXY=off",
			unmet: true,
		},
		{
			name: "прокси ОТВЕТИЛ «нет такой версии» — связь есть, это не третья категория",
			out: "go: example.com/nothing@v1.0.0: reading file:///tmp/proxy/example.com/nothing/@v/v1.0.0.mod: " +
				"no such file or directory",
			unmet: false,
		},
		{
			name:  "отказ сборки — находка, а не отсутствие сети",
			out:   "package example.com/service\n\tmain.go:3:8: use of internal package example.com/dependency/internal/inner not allowed",
			unmet: false,
		},
		{
			name:  "неразрешённый символ — находка",
			out:   "# example.com/service\n./main.go:5:34: undefined: helper",
			unmet: false,
		},
	}

	classified := 0
	for _, p := range probes {
		got := unmetReason(p.out)
		if (got != "") != p.unmet {
			t.Fatalf("%s: третья категория = %v, ожидалось %v (ответ %q)",
				p.name, got != "", p.unmet, got)
		}
		if p.unmet {
			classified++
		}
	}
	if classified == 0 {
		t.Fatalf("обход беспредметен: ни один вход не отнесён к третьей категории — "+
			"утверждение зеленело бы и на распознавателе, который не признаёт НИЧЕГО (входов %d)",
			len(probes))
	}
	t.Logf("перепись: входов %d, из них третья категория %d, находка %d",
		len(probes), classified, len(probes)-classified)
}
