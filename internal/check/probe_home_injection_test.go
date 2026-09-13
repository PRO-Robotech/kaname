// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// probe_home_injection_test.go — ПРОИЗВОДИТЕЛЬ ВХОДА для резолва дома и
// доказательство, что резолв способен упасть и способен смолчать.
//
// Ветвь резолва нельзя было заводить без производителя: объявленный и никогда не
// исполняемый страж есть мёртвый страж. Производитель — ДВА синтетических дерева
// с РАЗНЫМИ идентичностями, и решающая ось именно их различение: «посмотрел не
// туда» не должно быть неотличимо от «посмотрел туда и не нашёл».
//
// Деревья настоящие: настоящий git, настоящий `origin`, настоящая ссылка
// `origin/main`. Подделка здесь была бы снисходительнее продукта by construction —
// она отвечала бы «да» на вопрос, который в бою задаётся чужому репозиторию.
package check_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// mkHome — синтетическая копия с объявленной идентичностью и своим стволом.
//
// `origin` ставится URL-ом, а не именем каталога: дом опознаётся идентичностью,
// и проба обязана подавать её тем же способом, каким её читает продукт.
func mkHome(t *testing.T, base, dir, identity string, probes map[string]string) string {
	t.Helper()
	path := filepath.Join(base, dir)
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", path}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("remote", "add", "origin", "https://github.com/"+identity+".git")
	for name, body := range probes {
		if err := os.WriteFile(filepath.Join(path, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "-A")
	run("commit", "-q", "-m", "synthetic")
	// Ствол объявляется ЯВНО: продукт судит по `origin/main`, а не по индексу.
	run("update-ref", "refs/remotes/origin/main", "HEAD")
	return path
}

func homeProbeFile(names ...string) string {
	var b strings.Builder
	b.WriteString("package x\n\nimport \"testing\"\n\n")
	for _, n := range names {
		b.WriteString("func " + n + "(t *testing.T) {}\n")
	}
	return b.String()
}

func homeCoord(home, rev, name string) check.ProbeCoordinate {
	span := home
	if rev != "" {
		span += "@" + rev
	}
	return check.ProbeCoordinate{Name: name, Home: home, Rev: rev, Span: span + ":" + name}
}

// TestHomeResolver_TellsTheTwoTreesApart — РЕШАЮЩАЯ ось: два дома, разные имена.
func TestHomeResolver_TellsTheTwoTreesApart(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	mkHome(t, base, "alpha", "Some-Org/alpha", map[string]string{
		"a_test.go": homeProbeFile("TestOnlyInAlpha"),
	})
	mkHome(t, base, "beta", "Some-Org/beta", map[string]string{
		"b_test.go": homeProbeFile("TestOnlyInBeta"),
	})

	// Имя лежит в alpha и НЕ лежит в beta.
	v := check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", "", "TestOnlyInAlpha")})
	if v.Resolved != 1 || len(v.Findings) != 0 || len(v.Voids) != 0 {
		t.Fatalf("координата, лежащая в СВОЁМ доме, не разрешилась: %+v", v)
	}

	// То же имя, названное домом beta, — НАХОДКА, а не молчание. Без этой
	// половины резолв был бы неотличим от молчаливого отката на любое дерево.
	v = check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/beta", "", "TestOnlyInAlpha")})
	if len(v.Findings) != 1 {
		t.Fatalf("имя, которого в НАЗВАННОМ доме нет, не стало находкой: %+v", v)
	}
	if !strings.Contains(v.Findings[0], "Some-Org/beta") {
		t.Fatalf("находка не назвала дом, в котором искали: %q", v.Findings[0])
	}
	if v.Resolved != 0 {
		t.Fatalf("координата зачтена разрешённой в ЧУЖОМ доме: %+v", v)
	}

	// И зеркально: имя beta, названное домом beta, — молчание.
	v = check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/beta", "", "TestOnlyInBeta")})
	if v.Resolved != 1 || len(v.Findings) != 0 {
		t.Fatalf("законный близнец второго дома краснеет: %+v", v)
	}
}

// TestHomeResolver_IdentityNotDirectoryName — дом опознаётся `origin`.
func TestHomeResolver_IdentityNotDirectoryName(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	// Каталог зовут `alpha`, а копия — ЧУЖАЯ. Совпадение имени ничего не обещает.
	mkHome(t, base, "alpha", "Other-Org/alpha", map[string]string{
		"a_test.go": homeProbeFile("TestOnlyInAlpha"),
	})
	v := check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", "", "TestOnlyInAlpha")})
	if len(v.Voids) != 1 {
		t.Fatalf("копия с ЧУЖОЙ идентичностью принята за дом — имя каталога стало "+
			"вердиктом: %+v", v)
	}
	if !strings.Contains(v.Voids[0], "Other-Org/alpha") {
		t.Fatalf("причина не назвала, ЧЬЮ копию отвергли: %q", v.Voids[0])
	}
	if len(v.Findings) != 0 {
		t.Fatalf("«дома нет» подано как вердикт о приёмке: %+v", v)
	}
}

// TestHomeResolver_AbsentHomeIsTheThirdCategory — дома нет вовсе.
func TestHomeResolver_AbsentHomeIsTheThirdCategory(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	v := check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Nobody-Org/nothing", "", "TestX")})
	if len(v.Voids) != 1 || len(v.Findings) != 0 || v.Resolved != 0 {
		t.Fatalf("отсутствие дома обязано быть ТРЕТЬЕЙ категорией, а не находкой: %+v", v)
	}
	if !strings.Contains(v.Voids[0], "[VOID]") {
		t.Fatalf("третья категория не помечена: %q", v.Voids[0])
	}
	if !strings.Contains(v.Voids[0], "git clone") {
		t.Fatalf("причина не говорит, ЧЕМ создаётся условие: %q", v.Voids[0])
	}
	if len(v.HomesAbsent) != 1 {
		t.Fatalf("дом не назван в переписи отсутствующих: %+v", v)
	}
}

// TestHomeResolver_EnvVarNamesTheCopyExplicitly — первый кандидат закрытого порядка.
func TestHomeResolver_EnvVarNamesTheCopyExplicitly(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	// Копия лежит ТАМ, где соседний поиск её не найдёт: не `<предок>/<имя>` и не
	// `<предок>/project/<имя>`.
	home := mkHome(t, base, "elsewhere/deeply/hidden", "Some-Org/alpha", map[string]string{
		"a_test.go": homeProbeFile("TestOnlyInAlpha"),
	})
	v := check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", "", "TestOnlyInAlpha")})
	if len(v.Voids) != 1 {
		t.Fatalf("без переменной копия не должна находиться — иначе ось ничего не "+
			"доказывает: %+v", v)
	}
	t.Setenv(check.HomeEnvVar("Some-Org/alpha"), home)
	v = check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", "", "TestOnlyInAlpha")})
	if v.Resolved != 1 || len(v.Voids) != 0 {
		t.Fatalf("переменная не назвала копию: %+v", v)
	}
	if got := check.HomeEnvVar("PRO-Robotech/kacho-workspace"); got != "KACHO_HOME_KACHO_WORKSPACE" {
		t.Fatalf("имя переменной выведено неверно: %q", got)
	}
}

// TestHomeResolver_JudgesTheTrunkNotTheIndex — вердикт по стволу дома.
//
// Копия ОБЩАЯ: её ревизию переключает соседняя сессия. Вердикт, прочитанный с
// индекса, есть функция чужого переключения — класс наблюдался целиком.
func TestHomeResolver_JudgesTheTrunkNotTheIndex(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	home := mkHome(t, base, "alpha", "Some-Org/alpha", map[string]string{
		"a_test.go": homeProbeFile("TestOnTrunk"),
	})
	// В РАБОЧЕЙ КОПИИ и в индексе имя есть, в стволе — нет.
	if err := os.WriteFile(filepath.Join(home, "b_test.go"),
		[]byte(homeProbeFile("TestOnlyInWorkingCopy")), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", home, "add", "-A")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	v := check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", "", "TestOnTrunk")})
	if v.Resolved != 1 {
		t.Fatalf("имя ствола не разрешилось: %+v", v)
	}
	v = check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", "", "TestOnlyInWorkingCopy")})
	if len(v.Findings) != 1 {
		t.Fatalf("вердикт прочитан с ИНДЕКСА копии, а не со ствола: %+v", v)
	}
}

// TestHomeResolver_RevisionBoundIsJudgedAtThatRevision — связанная ревизией
// координата судится НА НЕЙ, а не на стволе.
//
// Это не тонкость: на стволе таких имён может уже не быть — они указывают в
// прошлое состояние чужого дерева НАМЕРЕННО. Сведение их к стволу дало бы
// находку о верном документе. Замер на дереве службы: все три связанные
// ревизией координаты резолвятся на своей ревизии и НЕ резолвятся на origin/main.
func TestHomeResolver_RevisionBoundIsJudgedAtThatRevision(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	home := mkHome(t, base, "alpha", "Some-Org/alpha", map[string]string{
		"a_test.go": homeProbeFile("TestWasThereOnce"),
	})
	rev, err := exec.Command("git", "-C", home, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	old := strings.TrimSpace(string(rev))

	// Ствол уезжает вперёд и имя снимает.
	if err := os.WriteFile(filepath.Join(home, "a_test.go"),
		[]byte(homeProbeFile("TestSomethingElse")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "retire"},
		{"update-ref", "refs/remotes/origin/main", "HEAD"}} {
		cmd := exec.Command("git", append([]string{"-C", home}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, cerr := cmd.CombinedOutput(); cerr != nil {
			t.Fatalf("git %v: %v\n%s", args, cerr, out)
		}
	}

	// Связана ревизией — молчание.
	v := check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", old, "TestWasThereOnce")})
	if v.Resolved != 1 || len(v.Findings) != 0 {
		t.Fatalf("связанная ревизией координата сведена к стволу: %+v", v)
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ: та же координата БЕЗ ревизии — находка.
	v = check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", "", "TestWasThereOnce")})
	if len(v.Findings) != 1 {
		t.Fatalf("координата без ревизии обязана судиться стволом: %+v", v)
	}
	// Ревизия, которой в копии дома НЕТ, — третья категория, а не находка.
	v = check.JudgeHomes(own, []check.ProbeCoordinate{
		homeCoord("Some-Org/alpha", "0123456789abcdef", "TestWasThereOnce")})
	if len(v.Voids) != 1 || len(v.Findings) != 0 {
		t.Fatalf("нерезолвящаяся ревизия подана вердиктом: %+v", v)
	}
}

// TestHomeResolver_MissingTrunkIsTheThirdCategory — ствола нет, судить не по чему.
func TestHomeResolver_MissingTrunkIsTheThirdCategory(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	home := mkHome(t, base, "alpha", "Some-Org/alpha", map[string]string{
		"a_test.go": homeProbeFile("TestX"),
	})
	if out, err := exec.Command("git", "-C", home, "update-ref", "-d",
		"refs/remotes/origin/main").CombinedOutput(); err != nil {
		t.Fatalf("снятие ствола: %v\n%s", err, out)
	}
	v := check.JudgeHomes(own, []check.ProbeCoordinate{homeCoord("Some-Org/alpha", "", "TestX")})
	if len(v.Voids) != 1 || len(v.Findings) != 0 {
		t.Fatalf("отсутствие ствола подано вердиктом о приёмке: %+v", v)
	}
	if !strings.Contains(v.Voids[0], "fetch origin main") {
		t.Fatalf("причина не говорит, чем создаётся условие: %q", v.Voids[0])
	}
}

// TestHomeResolver_AbsenceNeverMasksAFinding — находки и третья категория
// разведены, и одно не гасит другое.
func TestHomeResolver_AbsenceNeverMasksAFinding(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	mkHome(t, base, "alpha", "Some-Org/alpha", map[string]string{
		"a_test.go": homeProbeFile("TestPresent"),
	})
	v := check.JudgeHomes(own, []check.ProbeCoordinate{
		homeCoord("Nobody-Org/nothing", "", "TestWhatever"),
		homeCoord("Some-Org/alpha", "", "TestAbsentHere"),
	})
	if len(v.Findings) != 1 {
		t.Fatalf("находка погашена соседней третьей категорией: %+v", v)
	}
	if len(v.Voids) != 1 {
		t.Fatalf("третья категория потеряна: %+v", v)
	}
}

// TestHomeResolver_EmptyInputIsNotAVerdict — пустой вход не есть чистота.
func TestHomeResolver_EmptyInputIsNotAVerdict(t *testing.T) {
	v := check.JudgeHomes(t.TempDir(), nil)
	if v.Resolved != 0 || len(v.Findings) != 0 || len(v.Voids) != 0 {
		t.Fatalf("пустой вход что-то утверждает: %+v", v)
	}
	if len(v.HomesResolved) != 0 || len(v.HomesAbsent) != 0 {
		t.Fatalf("пустой вход назвал дома: %+v", v)
	}
}
