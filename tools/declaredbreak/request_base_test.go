// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// request_base_test.go — шаг конвейера судит запрос против БАЗЫ ЗАПРОСА, а не
// против `main` (задача kaname#1055).
//
// ИСПЫТУЕМЫЙ — СЦЕНАРИЙ, КОТОРЫЙ ЗОВЁТ ШАГ, а не его копия: путь сценария берётся
// из `run:` шага адъюдикации в `.github/workflows/ci.yml` (тот же опознаватель,
// что у проб провязки). `buf` настоящий: семантика сравнения — его, и подменять её
// двойником значило бы проверить двойника.
//
// СЦЕНА — как у конвейера на pull_request. Голый репозиторий служит `origin`;
// ветки `main`, эпик и голова запроса; коммит слияния головы с базой лежит под
// `refs/pull/1/merge`, и клон получает его так же, как `actions/checkout`, —
// глубиной 1. `origin` отдаёт коммит по имени (uploadpack.allowReachableSHA1InWant),
// как GitHub.
//
// ТАБЛИЦА — пункт · инъекция · исход:
//
//	отставание базы от main, удалений нет (законный близнец)  → 0, «вне перечня 0»
//	то же, но против main (контроль: прежнее поведение)       → 1, предмета в предке НЕТ
//	удаление поля относительно базы запроса (инъекция)        → 1, координата, предмет ЕСТЬ
//	запрос в main с удалением поля, которого в эпике нет      → 1: сравнение — с main
//	push в main (базы запроса нет)                            → 0, база main
//
// Пропуск под `-short` — потому что сцене нужен `buf`, а его ставит задание
// контрактов, где проба и исполняется без `-short`; провязку держит
// TestRequestBaseProbeRunsWhereBufIs.
package declaredbreak_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const probeBufYAML = `version: v2
modules:
  - path: .
breaking:
  use:
    - FILE
`

// protoWith — контракт, где у сообщения M ровно поля с номерами fields.
func protoWith(fields []int) string {
	var b strings.Builder
	b.WriteString("syntax = \"proto3\";\n\npackage probe.v1;\n\nmessage M {\n")
	for _, n := range fields {
		fmt.Fprintf(&b, "  string f%d = %d;\n", n, n)
	}
	b.WriteString("}\n")
	return b.String()
}

type scene struct {
	t      *testing.T
	origin string // голый репозиторий
	work   string // где делаются коммиты
	env    []string
}

func newScene(t *testing.T) *scene {
	t.Helper()
	dir := t.TempDir()
	gcfg := filepath.Join(dir, "gitconfig")
	if err := os.WriteFile(gcfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &scene{t: t, origin: filepath.Join(dir, "origin.git"), work: filepath.Join(dir, "work")}
	s.env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+gcfg, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=probe", "GIT_AUTHOR_EMAIL=probe@example.invalid",
		"GIT_COMMITTER_NAME=probe", "GIT_COMMITTER_EMAIL=probe@example.invalid",
		"TMPDIR="+dir)
	s.git("", "init", "-q", "--bare", s.origin)
	s.git(s.origin, "config", "uploadpack.allowReachableSHA1InWant", "true")
	s.git("", "init", "-q", "-b", "main", s.work)
	s.git(s.work, "remote", "add", "origin", "file://"+s.origin)
	return s
}

func (s *scene) git(dir string, args ...string) string {
	s.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("сцена не построена: git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit — дерево `proto` с полями fields и прочий файл note; коммит на текущей ветке.
func (s *scene) commit(fields []int, note string) string {
	s.t.Helper()
	files := map[string]string{
		"proto/buf.yaml":             probeBufYAML,
		"proto/declared-breaks.yaml": "breaks: []\n",
		"proto/probe/v1/m.proto":     protoWith(fields),
		"NOTE":                       note + "\n",
	}
	writeTree(s.t, s.work, files)
	s.git(s.work, "add", "-A")
	s.git(s.work, "commit", "-q", "-m", note)
	return s.git(s.work, "rev-parse", "HEAD")
}

// writeTree — файлы сцены под корнем root. Корень — рабочая копия сцены в
// t.TempDir(), его назначает вызывающий.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// pullRequest — коммит слияния головы head с базой base под refs/pull/1/merge.
func (s *scene) pullRequest(base, head string) {
	s.t.Helper()
	s.git(s.work, "checkout", "-q", "-B", "pr-merge", "origin/"+base)
	s.git(s.work, "merge", "-q", "--no-ff", "--no-edit", head)
	s.git(s.work, "push", "-q", "--force", "origin", "pr-merge:refs/pull/1/merge")
}

// checkout — клон глубиной 1 на ссылке, как у actions/checkout.
func (s *scene) checkout(ref string) string {
	s.t.Helper()
	clone := filepath.Join(s.t.TempDir(), "clone")
	s.git("", "init", "-q", clone)
	s.git(clone, "remote", "add", "origin", "file://"+s.origin)
	s.git(clone, "fetch", "-q", "--no-tags", "--depth=1", "origin", ref)
	s.git(clone, "checkout", "-q", "--detach", "FETCH_HEAD")
	return clone
}

// stepScript — сценарий, который зовёт шаг адъюдикации конвейера.
func stepScript(t *testing.T) string {
	t.Helper()
	var found []string
	for _, ss := range adjudicationSteps(readWorkflow(t)) {
		for _, st := range ss {
			for _, tok := range strings.Fields(st.Run) {
				if strings.HasPrefix(tok, "tools/declaredbreak/") && strings.HasSuffix(tok, ".sh") {
					found = append(found, tok)
				}
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("шаг адъюдикации зовёт сценариев %d (%v), а не один — испытуемый не установлен", len(found), found)
	}
	abs, err := filepath.Abs(filepath.Join("../..", found[0]))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

type outcome struct {
	rc  int
	out string
}

func (s *scene) judge(clone, adjudicator, script, baseRef, headSHA string) outcome {
	s.t.Helper()
	cmd := exec.Command("bash", script, adjudicator, "proto/declared-breaks.yaml")
	cmd.Dir = clone
	cmd.Env = append(append([]string{}, s.env...), "GITHUB_BASE_REF="+baseRef, "HEAD_SHA="+headSHA, "RUNNER_TEMP=")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	rc := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		rc = ee.ExitCode()
	} else if err != nil {
		s.t.Fatalf("сценарий не запущен: %v", err)
	}
	return outcome{rc: rc, out: out.String()}
}

func buildAdjudicator(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "adjudicate")
	out, err := exec.Command("go", "build", "-o", bin, "./cmd/adjudicate-declared-breaks").CombinedOutput()
	if err != nil {
		t.Fatalf("адъюдикатор не собран: %v\n%s", err, out)
	}
	return bin
}

func TestStepJudgesTheRequestAgainstItsBase(t *testing.T) {
	if testing.Short() {
		t.Skip("сцене нужен buf; пробу исполняет задание контрактов без -short")
	}
	if _, err := exec.LookPath("buf"); err != nil {
		t.Fatalf("ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: buf не найден в PATH (%v) — без -short проба зовётся там, где buf поставлен", err)
	}
	script, adj := stepScript(t), buildAdjudicator(t)

	expect := func(t *testing.T, o outcome, rc int, has ...string) {
		t.Helper()
		if o.rc != rc {
			t.Fatalf("код %d, ожидался %d\n%s", o.rc, rc, o.out)
		}
		for _, h := range has {
			if !strings.Contains(o.out, h) {
				t.Fatalf("в выводе нет %q\n%s", h, o.out)
			}
		}
	}

	// Общая история: ответвление эпика 942 от main с полями 1–3; затем main
	// получает поле 26 (чужой запрос), эпик об этом не знает.
	lagScene := func(t *testing.T, headFields []int) (*scene, string) {
		s := newScene(t)
		s.commit([]int{1, 2, 3}, "fork")
		s.git(s.work, "push", "-q", "origin", "main")
		s.git(s.work, "checkout", "-q", "-b", "942")
		s.git(s.work, "push", "-q", "origin", "942")
		s.git(s.work, "checkout", "-q", "main")
		s.commit([]int{1, 2, 3, 26}, "main gains field 26")
		s.git(s.work, "push", "-q", "origin", "main")
		s.git(s.work, "checkout", "-q", "-b", "848", "942")
		head := s.commit(headFields, "head of 848")
		s.git(s.work, "push", "-q", "origin", "848")
		s.pullRequest("942", "848")
		return s, head
	}

	t.Run("законный близнец: база отстала от main, удалений нет", func(t *testing.T) {
		s, head := lagScene(t, []int{1, 2, 3})
		o := s.judge(s.checkout("refs/pull/1/merge"), adj, script, "942", head)
		expect(t, o, 0, "база сравнения: 942 @", "вне перечня 0")
	})

	t.Run("контроль: та же сцена против main — отставание видно, предмета в предке нет", func(t *testing.T) {
		s, head := lagScene(t, []int{1, 2, 3})
		o := s.judge(s.checkout("refs/pull/1/merge"), adj, script, "main", head)
		expect(t, o, 1, "база сравнения: main @", "FIELD_NO_DELETE probe/v1/m.proto M.26", notInAncestorMark)
		if strings.Contains(o.out, inAncestorMark) {
			t.Fatalf("у отставания назван предмет в предке:\n%s", o.out)
		}
	})

	t.Run("инъекция: голова сняла поле, которое есть в базе запроса", func(t *testing.T) {
		s, head := lagScene(t, []int{1, 3})
		o := s.judge(s.checkout("refs/pull/1/merge"), adj, script, "942", head)
		expect(t, o, 1, "база сравнения: 942 @", "вне перечня 1", "FIELD_NO_DELETE probe/v1/m.proto M.2", inAncestorMark)
	})

	t.Run("запрос в main судится против main", func(t *testing.T) {
		s := newScene(t)
		s.commit([]int{1, 2, 3}, "fork")
		s.git(s.work, "push", "-q", "origin", "main")
		s.git(s.work, "push", "-q", "origin", "main:942")
		s.commit([]int{1, 2, 3, 26}, "main gains field 26")
		s.git(s.work, "push", "-q", "origin", "main")
		s.git(s.work, "checkout", "-q", "-b", "h")
		head := s.commit([]int{1, 2, 3}, "head drops field 26")
		s.git(s.work, "push", "-q", "origin", "h")
		s.pullRequest("main", "h")
		// В эпике 942 поля 26 нет: сравнение с ним молчало бы, и красное
		// здесь доказывает, что база — main.
		o := s.judge(s.checkout("refs/pull/1/merge"), adj, script, "main", head)
		expect(t, o, 1, "база сравнения: main @", "FIELD_NO_DELETE probe/v1/m.proto M.26", inAncestorMark)
	})

	t.Run("push в main: базы запроса нет — сравнение с main", func(t *testing.T) {
		s := newScene(t)
		s.commit([]int{1, 2, 3}, "fork")
		s.git(s.work, "push", "-q", "origin", "main")
		o := s.judge(s.checkout("refs/heads/main"), adj, script, "", "")
		expect(t, o, 0, "база сравнения: main @", "вне перечня 0")
	})
}
