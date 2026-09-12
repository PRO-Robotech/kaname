// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authz_wrapper_outcome_lanes_injection_test.go — доказательство падучести на
// синтетическом git-репозитории.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
	"github.com/PRO-Robotech/kacho/pkg/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func synthWrapperRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := gitenv.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module github.com/example/synth\n\ngo 1.23\n")

	// Пакет-владелец пары: булева обёртка + форма с исходом.
	write("internal/guard/guard.go", `package guard

func IsClusterAdmin(subject string) bool {
	ok, _ := IsClusterAdminE(subject)
	return ok
}

func IsClusterAdminE(subject string) (bool, error) {
	return subject == "root", nil
}
`)
	// ЗАКОННЫЙ вызывающий: внутри пакета-владельца, зовёт форму С исходом.
	write("internal/guard/user.go", `package guard

func check(subject string) error {
	ok, err := IsClusterAdminE(subject)
	if err != nil {
		return err
	}
	_ = ok
	return nil
}
`)
	// ИНЪЕКЦИЯ: чужой пакет зовёт БУЛЕВУ половину, хотя форма с исходом есть.
	write("internal/api/handler.go", `package api

import "github.com/example/synth/internal/guard"

func serve(subject string) bool {
	return guard.IsClusterAdmin(subject)
}
`)
	// ЗАКОННЫЙ БЛИЗНЕЦ: другой чужой пакет зовёт ФОРМУ С ИСХОДОМ — молчание.
	write("internal/api2/handler.go", `package api2

import "github.com/example/synth/internal/guard"

func serve(subject string) error {
	_, err := guard.IsClusterAdminE(subject)
	return err
}
`)
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "gate@example.invalid")
	run("config", "user.name", "gate")
	run("add", "-A")
	run("commit", "--quiet", "-m", "синтетика")
	return root
}

// TestAuthzWrapperOutcomeLanesInjection — контроль пакета-владельца
// (молчание внутри себя), инъекция (чужой пакет зовёт булеву половину),
// законный близнец (чужой пакет зовёт форму с исходом — молчание).
func TestAuthzWrapperOutcomeLanesInjection(t *testing.T) {
	t.Parallel()
	root := synthWrapperRepo(t)

	all, err := treecorpus.Under(root)
	if err != nil {
		t.Fatalf("состав синтетики: %v", err)
	}
	roots, err := check.ProdGoRoots(root, all)
	if err != nil {
		t.Fatalf("%v", err)
	}
	rep, err := check.ScanBoolWrapperCalls(root, roots, treecorpus.Under)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(rep.Pairs) != 1 {
		t.Fatalf("ожидалась ровно одна выведенная пара, получено %d: %+v", len(rep.Pairs), rep.Pairs)
	}
	if len(rep.Found) != 1 {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась ровно одна находка (internal/api зовёт булеву половину), "+
			"получено %d: %+v", len(rep.Found), rep.Found)
	}
	if !strings.Contains(rep.Found[0].File, "internal/api/handler.go") {
		t.Errorf("находка указывает не на internal/api: %+v", rep.Found[0])
	}
	for _, c := range rep.Found {
		if strings.Contains(c.File, "internal/api2/") {
			t.Errorf("ЗАКОННЫЙ БЛИЗНЕЦ: гейт покраснел на пакете, зовущем форму С ИСХОДОМ: %+v", c)
		}
		if strings.Contains(c.File, "internal/guard/") {
			t.Errorf("ГРАНИЦА: гейт покраснел на вызове ВНУТРИ пакета-владельца: %+v", c)
		}
	}
}
