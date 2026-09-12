// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_edit_after_verdict_injection_test.go — доказательство способности
// TestAcceptanceEditedAfterItsVerdictSaysSo упасть и смолчать, на синтетическом
// git-репозитории во временном каталоге (`multi-agent-flow.md` §13 — своей
// рабочей копии не трогаем).
package check_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// synthAcceptanceRepo — синтетический репозиторий с одной приёмкой, правленой
// строку за строкой во ВРЕМЕНИ (три коммита), чтобы у строки состояния и у
// файла оказались РАЗНЫЕ отметки git log.
type synthAcceptanceRepo struct {
	root string
}

func newSynthAcceptanceRepo(t *testing.T) *synthAcceptanceRepo {
	t.Helper()
	root := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := gitenv.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "gate@example.invalid")
	run("config", "user.name", "gate")
	return &synthAcceptanceRepo{root: root}
}

func (r *synthAcceptanceRepo) write(t *testing.T, rel, body string) {
	t.Helper()
	full := filepath.Join(r.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (r *synthAcceptanceRepo) commit(t *testing.T, at time.Time, msg string) {
	t.Helper()
	env := append(os.Environ(),
		"GIT_AUTHOR_DATE="+strconv.FormatInt(at.Unix(), 10),
		"GIT_COMMITTER_DATE="+strconv.FormatInt(at.Unix(), 10))
	add := gitenv.Command(r.root, "add", "-A")
	add.Env = env
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	c := gitenv.Command(r.root, "commit", "--quiet", "-m", msg)
	c.Env = env
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}

// TestAcceptanceEditAfterVerdictInjection — три прогона: контроль (правки не
// после вердикта либо названы), инъекция (правка после вердикта БЕЗ записи),
// законный близнец (правка названа прозой).
func TestAcceptanceEditAfterVerdictInjection(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// ── КОНТРОЛЬ: документ создан один раз, строка состояния и файл имеют
	// одну и ту же отметку — fileAt <= stateAt, находок нет.
	t.Run("контроль: не правлено после вердикта", func(t *testing.T) {
		t.Parallel()
		r := newSynthAcceptanceRepo(t)
		r.write(t, "docs/engineering/acceptance/live.md",
			"# Приёмка\n\n**Статус:** APPROVED\n\nТело.\n")
		r.commit(t, base, "приёмка")

		findings, census, err := check.AuditAcceptanceEditsAfterVerdict(r.root, "docs/engineering/acceptance")
		if err != nil {
			t.Fatalf("%v", err)
		}
		if census.DocsRead != 1 {
			t.Fatalf("ожидался 1 документ, получено %d", census.DocsRead)
		}
		if len(findings) != 0 {
			t.Fatalf("КОНТРОЛЬ: гейт покраснел на неправленом документе: %v", findings)
		}
	})

	// ── ИНЪЕКЦИЯ: документ правлен ПОСЛЕ вердикта, без записи об этом.
	t.Run("инъекция: правлено после вердикта без записи — находка", func(t *testing.T) {
		t.Parallel()
		r := newSynthAcceptanceRepo(t)
		r.write(t, "docs/engineering/acceptance/live.md",
			"# Приёмка\n\n**Статус:** APPROVED\n\nТело первой редакции.\n")
		r.commit(t, base, "приёмка APPROVED")

		r.write(t, "docs/engineering/acceptance/live.md",
			"# Приёмка\n\n**Статус:** APPROVED\n\nТело ВТОРОЙ редакции, молча.\n")
		r.commit(t, base.Add(24*time.Hour), "правка тела")

		findings, _, err := check.AuditAcceptanceEditsAfterVerdict(r.root, "docs/engineering/acceptance")
		if err != nil {
			t.Fatalf("%v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("ИНЪЕКЦИЯ: ожидалась ровно одна находка, получено %d: %v", len(findings), findings)
		}
		if !strings.Contains(findings[0].File, "live.md") {
			t.Errorf("находка не называет файл: %+v", findings[0])
		}
	})

	// ── ЗАКОННЫЙ БЛИЗНЕЦ: та же правка после вердикта, но НАЗВАНА прозой —
	// молчание.
	t.Run("законный близнец: правка после вердикта названа — молчит", func(t *testing.T) {
		t.Parallel()
		r := newSynthAcceptanceRepo(t)
		r.write(t, "docs/engineering/acceptance/live.md",
			"# Приёмка\n\n**Статус:** APPROVED\n\nТело первой редакции.\n")
		r.commit(t, base, "приёмка APPROVED")

		r.write(t, "docs/engineering/acceptance/live.md",
			"# Приёмка\n\n**Статус:** APPROVED\n\nТело правлено ПОСЛЕ вердикта: см. §N.\n")
		r.commit(t, base.Add(24*time.Hour), "правка с записью")

		findings, _, err := check.AuditAcceptanceEditsAfterVerdict(r.root, "docs/engineering/acceptance")
		if err != nil {
			t.Fatalf("%v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: гейт покраснел на документе, назвавшем свою правку: %v", findings)
		}
	})

	// ── Предпосылка: документ без строки состояния — предмет ДРУГОГО
	// держателя, не находка этого гейта.
	t.Run("без строки состояния — не находка", func(t *testing.T) {
		t.Parallel()
		r := newSynthAcceptanceRepo(t)
		r.write(t, "docs/engineering/acceptance/live.md", "# Приёмка\n\nБез статуса.\n")
		r.commit(t, base, "без статуса")
		r.write(t, "docs/engineering/acceptance/live.md", "# Приёмка\n\nБез статуса, правлено.\n")
		r.commit(t, base.Add(time.Hour), "правка")

		findings, census, err := check.AuditAcceptanceEditsAfterVerdict(r.root, "docs/engineering/acceptance")
		if err != nil {
			t.Fatalf("%v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("документ без строки состояния дал находку: %v", findings)
		}
		if len(census.NoStateLine) != 1 {
			t.Fatalf("ожидался 1 документ без строки состояния, получено %d", len(census.NoStateLine))
		}
	})
}
