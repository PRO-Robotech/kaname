// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tools_regression locks the behaviour of kacho-iam's audit-list-filter
// gate against the REAL tree.
//
// The fixtures in pkg/listfiltergate assert the analyser's discrimination on
// synthetic trees. What they cannot assert is that iam's own PROFILE points at
// declarations that exist, that its own listings stay clean, and that the ban it
// derives is the ban it thinks it derives. A profile can name a type that has moved
// and a synthetic fixture will never notice.
//
// Everything runs through the SAME wrapper CI issues (tools/audit-list-filter.sh),
// so the whole chain is under test: wrapper → go run → flags → analysis.
//
// Four properties, and each is needed:
//
//   - the real tree passes, and the LEGITIMATE callers of an enumeration stay silent.
//     AuthorizeService.ListObjects/.ListSubjects reach the store's enumeration by
//     design — it is what the caller asked for — so the same call that is refused
//     inside a narrowing listing must be accepted there. Without this half, the
//     injections below would only prove the gate fires on a token;
//   - a listing that takes its page from an enumeration is REFUSED, and the finding
//     names the call and the coordinate. Injected in both flavours: the store's
//     (`ListObjects`) and iam's own database (`Objects` — the third form, invisible
//     to the gate until #651 because a name it was never told about is a name it
//     cannot refuse);
//   - the derivation expires with its subject. A source type that moved is a
//     FINDING, because a source resolving to nothing would take its whole derived
//     ban with it while the run went on printing OK;
//   - "zero findings" is unreachable from "zero read": a gate pointed at a tree it
//     cannot open reports a finding, never OK.
package tools_regression

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// treesRead are the directories the gate parses for iam: the listing surface, and
// the two declared enumeration sources whose method sets derive the ban.
var treesRead = []string{
	"internal/apps/kacho/api",
	"internal/clients",
	"internal/repo/kacho/pg/relverdict",
}

// serviceRoot returns services/iam (the directory holding internal/… and tools/).
func serviceRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(self))
}

// repoRoot returns the module root, so the proto tree the profile's EdgeGate
// declarations are verified against is resolved from the REAL repository. The proto
// is not what is being injected; pointing the gate at a copy without it would make
// every run report an unverifiable EdgeGate and hide the property under test.
func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Dir(filepath.Dir(serviceRoot(t)))
}

// runGate runs the production wrapper against the tree rooted at root.
//
// The working directory is set to root as well as passing --root: a gate that read
// the CURRENT directory instead of the one it was given must still be judged on the
// tree under test, never on the real service.
func runGate(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	argv := append([]string{
		filepath.Join(serviceRoot(t), "tools", "audit-list-filter.sh"),
		"--root=" + root,
		"--proto-root=" + filepath.Join(repoRoot(t), "proto"),
	}, args...)
	cmd := exec.Command("bash", argv...)
	cmd.Dir = root
	raw, err := cmd.CombinedOutput()
	return string(raw), err
}

// copyTrees materialises a throwaway copy of everything the gate reads, so an
// injection can be made against the REAL declarations without touching the repo.
//
// The file set comes from the git INDEX (pkg/treecorpus), not from a disk
// walk. Under services/ a walk also reads what the repository does not contain —
// agent working copies, generated directories, run reports — every one of them
// already declared out of the tree by .gitignore and invisible to filepath.WalkDir.
// Both directions of that have been live defects here, so the tree-wide gate
// TestTreeWalkersAskTheIndex refuses a new disk walk: it caught this very function
// on its first run.
func copyTrees(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := serviceRoot(t)
	copied := 0
	for _, tree := range treesRead {
		paths, err := treecorpus.UnderWithSuffix(filepath.Join(src, tree), ".go")
		if err != nil {
			t.Fatalf("состав %s: %v", tree, err)
		}
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			rel, rerr := filepath.Rel(src, path)
			if rerr != nil {
				t.Fatalf("rel %s: %v", path, rerr)
			}
			out := filepath.Join(dst, rel)
			if merr := os.MkdirAll(filepath.Dir(out), 0o755); merr != nil {
				t.Fatalf("mkdir %s: %v", out, merr)
			}
			b, rderr := os.ReadFile(path)
			if rderr != nil {
				t.Fatalf("read %s: %v", path, rderr)
			}
			if werr := os.WriteFile(out, b, 0o644); werr != nil {
				t.Fatalf("write %s: %v", out, werr)
			}
			copied++
		}
	}
	// "Ноль прочитанного" обязано быть отличимо от "ноль находок": копия, собранная
	// из пустого состава, дала бы гейту пустое дерево, и КАЖДАЯ проба ниже упала бы
	// с сообщением не о своём предмете.
	if copied == 0 {
		t.Fatalf("состав пуст: скопировано 0 файлов из %v — инъекции ниже утверждали бы "+
			"о дереве, которого нет", treesRead)
	}
	return dst
}

// patch rewrites one file of the copied tree and REQUIRES the replacement to apply,
// so an injection that stopped modelling anything fails loudly instead of passing.
func patch(t *testing.T, root, rel, old, replacement string) {
	t.Helper()
	path := filepath.Join(root, rel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := string(b)
	if !strings.Contains(s, old) {
		t.Fatalf("injection point %q is gone from %s — the injection no longer models anything", old, rel)
	}
	if werr := os.WriteFile(path, []byte(strings.ReplaceAll(s, old, replacement)), 0o644); werr != nil {
		t.Fatalf("write %s: %v", path, werr)
	}
}

// TestGate_RealTreePasses_AndLegitimateEnumeratorsStaySilent — the positive control,
// and it carries the half that matters most: the SAME call the injections below are
// refused for is reached, legitimately, by AuthorizeService.ListObjects and
// .ListSubjects, whose response IS the store's answer. A ban that could not tell
// those apart would be a ban somebody switches off.
func TestGate_RealTreePasses_AndLegitimateEnumeratorsStaySilent(t *testing.T) {
	out, err := runGate(t, serviceRoot(t))
	if err != nil {
		t.Fatalf("the real tree must pass; got %v\n%s", err, out)
	}
	for _, want := range []string{
		// the derivation ran, and the census says what it read — so a run that
		// derived nothing is distinguishable from this one
		"enumerate-then-narrow ban",
		"source internal/clients.RelationQueries",
		"source internal/repo/kacho/pg/relverdict.Asker",
		// both flavours are in the effective ban
		"ListObjects",
		"Objects",
		// and the legitimate caller was judged, not skipped.
		//
		// Их было двое, пока существовало перечисление объектов; RPC снят с
		// контракта стадией S6 (эпик #747), и объявление профиля снято вместе с
		// ним. Имя `ListObjects` при этом ОСТАЁТСЯ в запрете выше — как чужой
		// словарь, который нельзя вывести из дерева и потому обязан быть выписан.
		"authorize.ListSubjects",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("census must state %q; got:\n%s", want, out)
		}
	}
}

// TestGate_RefusesAPageTakenFromAnEnumeration — the injection, in both flavours.
//
// Both are made in a listing use-case that is clean today, and both are the shape
// `security.md` refuses: the page comes out of "which objects may this subject see"
// instead of being read from iam's own tables and put to the model afterwards.
//
// The coordinate the finding carries is the LISTING DECLARATION — the handler method
// — not the line the banned call sits on. That is this gate's convention for every
// finding it reports, and it is the right unit here: the declaration is what carries
// the shape, and the call may be several hops down its call graph.
func TestGate_RefusesAPageTakenFromAnEnumeration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		file       string
		anchor     string
		injected   string
		wantCall   string
		wantSource string
		wantInFile string
	}{
		{
			// iam's OWN database — the third form. relverdict is legitimate where it
			// is used today (the shadow comparison, which is not a listing) and is
			// exactly the old defect inside one. Nothing in the tree calls it from a
			// listing, which is why the ban had to arrive BEFORE the first caller.
			name:       "own database",
			file:       "internal/apps/kacho/api/user/list.go",
			anchor:     "\tsubject := userPrincipalSubject(principal)",
			injected:   "\tids, _, _ := uc.verdicts.Objects(ctx, \"user:x\", fgaUserType, []string{\"viewer\"}, 500)\n\t_ = ids\n\tsubject := userPrincipalSubject(principal)",
			wantCall:   "reaches Objects",
			wantSource: "internal/repo/kacho/pg/relverdict.Asker",
			wantInFile: "user/handler.go",
		},
		{
			// the store's enumeration, reached from a narrowing listing. Named in the
			// hand-written floor too, so this half also proves the floor still holds
			// after the derivation was added.
			name:       "authorization store",
			file:       "internal/apps/kacho/api/group/list.go",
			anchor:     "\tsubject := principalSubject(principal)",
			injected:   "\tids, _ := u.relationQueries.ListObjects(ctx, \"user:x\", \"viewer\", fgaGroupType, nil, 1000)\n\t_ = ids\n\tsubject := principalSubject(principal)",
			wantCall:   "reaches ListObjects",
			wantSource: "",
			wantInFile: "group/handler.go",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := copyTrees(t)
			patch(t, root, tc.file, tc.anchor, tc.injected)

			out, err := runGate(t, root)
			if err == nil {
				t.Fatalf("a listing taking its page from an enumeration must be refused; got:\n%s", out)
			}
			if !strings.Contains(out, tc.wantCall) {
				t.Fatalf("the finding must name the call (%s); got:\n%s", tc.wantCall, out)
			}
			if !strings.Contains(out, tc.wantInFile) {
				t.Fatalf("the finding must carry the coordinate (%s); got:\n%s", tc.wantInFile, out)
			}
			if tc.wantSource != "" && !strings.Contains(out, tc.wantSource) {
				t.Fatalf("a DERIVED ban must name the declaration it came from (%s); got:\n%s", tc.wantSource, out)
			}
		})
	}
}

// TestGate_EnumerationSourceExpiresWithItsSubject — a source that moved is a finding,
// not a quiet loss of the ban it derives. Without this the profile could point at a
// renamed type, derive nothing, and the run would look exactly like a clean one.
func TestGate_EnumerationSourceExpiresWithItsSubject(t *testing.T) {
	root := copyTrees(t)
	// The type AND its receivers, because the derivation reads both forms: renaming
	// only the type declaration would leave the methods attributed to it and the ban
	// intact — which is correct behaviour, and would make this injection model nothing.
	//
	// ПОЭТОМУ ФАЙЛОВ ДВА, а не один. Приёмники типа живут и в соседнем файле
	// (`asker_gate.go`, заведён стадией S6 эпика #747), и пока хоть один из них
	// называет прежнее имя, набор методов типа находится — то есть инъекция
	// перестаёт моделировать «источник переехал». Замечено прогоном: после
	// появления второго файла эта проба зазеленела, ничего не проверив.
	//
	// Перечень намеренно ВЫПИСАН, а не выведен: вывод по каталогу утащил бы сюда
	// пробы, и инъекция стала бы править то, чего не собиралась.
	for _, rel := range []string{
		"internal/repo/kacho/pg/relverdict/asker.go",
		"internal/repo/kacho/pg/relverdict/asker_gate.go",
	} {
		patch(t, root, rel, "Asker", "AskerMoved")
	}

	out, err := runGate(t, root)
	if err == nil {
		t.Fatalf("a source that no longer resolves must be a finding; got:\n%s", out)
	}
	if !strings.Contains(out, "nothing left to describe") {
		t.Fatalf("the finding must say the entry has nothing left to describe; got:\n%s", out)
	}
}

// TestGate_UnreadableTreeIsAFinding — "zero findings" must be unreachable from
// "zero read". A gate pointed at the wrong tree that printed OK would be worse than
// no gate: it would be an assurance nobody could distinguish from a real one.
func TestGate_UnreadableTreeIsAFinding(t *testing.T) {
	out, err := runGate(t, t.TempDir())
	if err == nil {
		t.Fatalf("an empty tree must be a finding, never OK; got:\n%s", out)
	}
	if !strings.Contains(out, "examined nothing") {
		t.Fatalf("the finding must say the gate examined nothing; got:\n%s", out)
	}
}
