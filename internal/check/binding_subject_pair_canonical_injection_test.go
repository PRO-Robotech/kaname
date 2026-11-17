// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Эти функции добавляются в уже существующую типизированную overlay-пробу.
// У основных дефектов остаются те же два чтения пары: счётчик сам их не ловит.
const bindingPairCanonicalProbeSrc = `
func probeCanonicalValue(b domain.AccessBinding) ([]domain.Subject, error) {
	return domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
}
func probeCanonicalPointer(b *domain.AccessBinding) ([]domain.Subject, error) {
	return domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
}
func probeCanonicalNil(b domain.AccessBinding) ([]domain.Subject, error) {
	return domain.NormalizeSubjects(nil, b.SubjectType, b.SubjectID)
}
func probeCanonicalSubset(b domain.AccessBinding) ([]domain.Subject, error) {
	return domain.NormalizeSubjects(b.Subjects[:1], b.SubjectType, b.SubjectID)
}
func probeCanonicalForeignSet(b, other domain.AccessBinding) ([]domain.Subject, error) {
	return domain.NormalizeSubjects(other.Subjects, b.SubjectType, b.SubjectID)
}
func probeCanonicalForeignPair(b, other domain.AccessBinding) ([]domain.Subject, error) {
	return domain.NormalizeSubjects(b.Subjects, b.SubjectType, other.SubjectID)
}
func probeCanonicalFunctionVariable(b domain.AccessBinding) ([]domain.Subject, error) {
	normalize := domain.NormalizeSubjects
	return normalize(b.Subjects, b.SubjectType, b.SubjectID)
}
type probeCanonicalNormalizer struct{}
func (probeCanonicalNormalizer) NormalizeSubjects(subjects []domain.Subject, _ domain.SubjectType, _ domain.SubjectID) ([]domain.Subject, error) {
	return subjects, nil
}
func probeCanonicalNamesake(b domain.AccessBinding) ([]domain.Subject, error) {
	other := probeCanonicalNormalizer{}
	return other.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
}
func probeCanonicalExtraRead(b domain.AccessBinding) ([]domain.Subject, error) {
	_ = b.SubjectID
	return domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
}
func probeCanonicalDuplicate(b domain.AccessBinding) ([]domain.Subject, error) {
	_, _ = domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
	return domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
}
`

// Одна точная запись проверяется отдельно от остальных новых мест дерева.
// Полный production gate продолжает судить весь census без фильтрации.
func bindingPairCanonicalVerdict(census check.BindingPairCensus, place string, entry check.BindingPairEntry) []string {
	only := check.BindingPairCensus{Accesses: census.Places()[place]}
	return check.JudgeBindingSubjectPair(only, map[string]check.BindingPairEntry{place: entry})
}

func TestBindingSubjectPairCanonicalNormalizationHasTypedProof(t *testing.T) {
	_, injected := bindingPairCensuses(t)
	cases := []struct {
		name string
		goN  int
		ok   bool
	}{
		{"probeCanonicalValue", 2, true},
		{"probeCanonicalPointer", 2, true},
		{"probeCanonicalNil", 2, false},
		{"probeCanonicalSubset", 2, false},
		{"probeCanonicalForeignSet", 2, false},
		{"probeCanonicalForeignPair", 2, false},
		{"probeCanonicalFunctionVariable", 2, false},
		{"probeCanonicalNamesake", 2, false},
		{"probeCanonicalExtraRead", 3, false},
		{"probeCanonicalDuplicate", 4, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			place := bindingPairPlace(tc.name)
			accesses := injected.Places()[place]
			if len(accesses) != tc.goN {
				t.Fatalf("условие не создано: %s: доступов %d, нужно %d", place, len(accesses), tc.goN)
			}
			entry := check.BindingPairEntry{Go: 2, Class: check.BindingPairCanonicalFallback, Why: "проба точного вызова"}
			findings := bindingPairCanonicalVerdict(injected, place, entry)
			if tc.ok {
				if len(findings) != 0 {
					t.Fatalf("канонический близнец не молчит: %v", findings)
				}
				// Доказательство формы не освобождает новое место от ведомости.
				unlisted := check.JudgeBindingSubjectPair(check.BindingPairCensus{Accesses: accesses}, nil)
				if len(unlisted) != 1 || !strings.Contains(unlisted[0], "вне перечня") {
					t.Fatalf("новое место получило автоматическое исключение: %v", unlisted)
				}
				return
			}
			if len(findings) != 1 || !strings.Contains(findings[0], "каноническая нормализация не доказана") ||
				!strings.Contains(findings[0], bindingPairProbeFile+":") {
				t.Fatalf("ИНЪЕКЦИЯ НЕ ПОЙМАНА с точной причиной и координатой: %v", findings)
			}
		})
	}
}

// В живых трёх местах заменяется только полный набор на nil. Два доступа
// пары и прежняя запись ведомости остаются; все три мутации проходят один
// typed overlay scan. Никакой production-файл тестом не изменяется.
func TestBindingSubjectPairCanonicalRealSourcesRejectDroppedSet(t *testing.T) {
	targets := []struct {
		file string
		fn   string
	}{
		{"binding_decision.go", "GrantPolicyWriters.bindingDecisionOnce"},
		{"binding_withdrawal_stage.go", "BindingStageParticipant.stageWithdrawal"},
		{"grant_mutation_preflight.go", "bindingDecisionPreflight"},
	}
	const rel = "internal/repo/kaname/pg"
	const before = "domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)"
	const after = "domain.NormalizeSubjects(nil, b.SubjectType, b.SubjectID)"
	root := ceremonyModuleRoot(t)
	dir := t.TempDir()
	if err := bindingPairCopy(root, rel, dir); err != nil {
		t.Fatalf("условие не создано: копия pg: %v", err)
	}
	control, _ := bindingPairCensuses(t)
	for _, target := range targets {
		place := rel + "/" + target.file + "::" + target.fn
		entry, ok := check.BindingSubjectPairLedger[place]
		if !ok || entry.Class != check.BindingPairCanonicalFallback {
			t.Fatalf("нет строгой записи проверяемого production-места %s", place)
		}
		if findings := bindingPairCanonicalVerdict(control, place, entry); len(findings) != 0 {
			t.Fatalf("исходное место не доказано; мутация не имеет контроля: %v", findings)
		}
		path := filepath.Join(dir, target.file)
		data, err := os.ReadFile(path) // #nosec G304 -- точный файл собственной временной копии
		if err != nil {
			t.Fatal(err)
		}
		receiver, function, method := strings.Cut(target.fn, ".")
		if !method {
			function, receiver = receiver, ""
		}
		changed := mutateRouteFunction(t, target.file, string(data), receiver, function, func(declaration string) string {
			if strings.Count(declaration, before) != 1 {
				t.Fatalf("условие не создано: %s::%s не содержит ровно один исходный вызов", path, target.fn)
			}
			return strings.Replace(declaration, before, after, 1)
		})
		if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	injected, err := check.CollectBindingSubjectPair(t.Context(), check.BindingPairSpec{
		ModuleRoot: root,
		Overlay:    map[string]string{ceremonyModulePath(t, root) + "/" + rel: dir},
	})
	if err != nil {
		t.Fatalf("гейт НЕ ИСПОЛНИЛСЯ на мутации: %v", err)
	}
	for _, target := range targets {
		place := rel + "/" + target.file + "::" + target.fn
		if len(injected.Places()[place]) != 2 {
			t.Fatalf("мутация должна сохранить два чтения пары: %s: %v", place, injected.Places()[place])
		}
		findings := bindingPairCanonicalVerdict(injected, place, check.BindingSubjectPairLedger[place])
		if len(findings) != 1 || !strings.Contains(findings[0], "каноническая нормализация не доказана") ||
			!strings.Contains(findings[0], rel+"/"+target.file+":") {
			t.Errorf("ИНЪЕКЦИЯ НЕ ПОЙМАНА в реальном месте %s: %v", place, findings)
		}
	}
}
