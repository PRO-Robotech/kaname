// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzfilter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Fixtures проходят тот же package-local resolver и тот же scanner, что продукт.
// staged question намеренно находится через два local метода в другом файле.
const retryGateFixture = `package fixture

import (
	stderrors "errors"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

const retryLimit = 3

func (u *worker) run(ctx context.Context, id string) (string, error) {
	for attempt := 1; ; attempt++ {
		result, err := u.once(ctx, id)
		if err == nil {
			return result, nil
		}
		if !stderrors.Is(err, iamerr.ErrAborted) || attempt == retryLimit {
			return "", err
		}
	}
}
`

const retryGateStagedFixture = `package fixture

func (u *worker) once(ctx context.Context, id string) (string, error) {
	if u.staged {
		return u.stage(ctx, id)
	}
	return "", nil
}

func (u *worker) stage(ctx context.Context, id string) (string, error) {
	_, err := authzguard.AllowsVGet(ctx, u.relations, "account", id)
	return "", err
}
`

func TestBoundedRetryGateDistinguishesAttemptsFromPageLoops(t *testing.T) {
	change := func(old, new string) string {
		require.Equal(t, 1, strings.Count(retryGateFixture, old), "injection anchor must be unique")
		return strings.Replace(retryGateFixture, old, new, 1)
	}
	pageMethod := `
func (u *worker) page(ctx context.Context, ids []string) {
	for _, id := range ids {
		_, _ = u.once(ctx, id)
	}
}
`
	for _, tc := range []struct {
		name      string
		source    string
		staged    string
		findings  int
		cleared   int
		loopCalls int
	}{
		{name: "whole attempt with hidden staged question", source: retryGateFixture, cleared: 1, loopCalls: 1},
		{name: "aliases and all operation names may change", source: strings.NewReplacer(
			"stderrors", "retryErrors", "iamerr", "faults", "attempt", "round", "retryLimit", "capSteps",
			"run", "applyAgain", "once", "oneTransaction").Replace(retryGateFixture),
			staged: strings.ReplaceAll(retryGateStagedFixture, "once", "oneTransaction"), cleared: 1, loopCalls: 1},
		{name: "literal constant cap", source: change("attempt == retryLimit", "attempt == 3"), cleared: 1, loopCalls: 1},
		{name: "smaller compile time cap", source: change("retryLimit = 3", "retryLimit = 2"), cleared: 1, loopCalls: 1},
		{name: "missing cap", source: change(" || attempt == retryLimit", ""), findings: 1, loopCalls: 1},
		{name: "non-aborted retry", source: change("iamerr.ErrAborted", "iamerr.ErrUnavailable"), findings: 1, loopCalls: 1},
		{name: "lookalike errors import", source: change(`"errors"`, `"example.invalid/errors"`), findings: 1, loopCalls: 1},
		{name: "lookalike sentinel import", source: change(`"github.com/PRO-Robotech/kaname/internal/errors"`, `"example.invalid/iam/errors"`), findings: 1, loopCalls: 1},
		{name: "mutable cap", source: change("const retryLimit", "var retryLimit"), findings: 1, loopCalls: 1},
		{name: "too many attempts", source: change("retryLimit = 3", "retryLimit = 4"), findings: 1, loopCalls: 1},
		{name: "unreachable zero cap", source: change("retryLimit = 3", "retryLimit = 0"), findings: 1, loopCalls: 1},
		{name: "dynamic bound", source: change("attempt == retryLimit", "attempt == len(ids)"), findings: 1, loopCalls: 1},
		{name: "wrong bound comparison", source: change("attempt == retryLimit", "attempt > retryLimit"), findings: 1, loopCalls: 1},
		{name: "and condition loses terminal cap", source: change(" || attempt == retryLimit", " && attempt == retryLimit"), findings: 1, loopCalls: 1},
		{name: "success continues", source: change("return result, nil", "continue"), findings: 1, loopCalls: 1},
		{name: "cap branch continues", source: change(`return "", err`, "continue"), findings: 1, loopCalls: 1},
		{name: "extra first attempt", source: change("attempt := 1", "attempt := 0"), findings: 1, loopCalls: 1},
		{name: "wrong increment", source: change("attempt++", "attempt--"), findings: 1, loopCalls: 1},
		{name: "counter reset", source: change("\t}\n}\n", "\t\tattempt = 1\n\t}\n}\n"), findings: 1, loopCalls: 1},
		{name: "counter escapes by address", source: change("\t}\n}\n", "\t\treset(&attempt)\n\t}\n}\n"), findings: 1, loopCalls: 1},
		{name: "argument changes between attempts", source: change("\t}\n}\n", "\t\tid = nextID()\n\t}\n}\n"), findings: 1, loopCalls: 1},
		{name: "parameter address escapes", source: change("\t}\n}\n", "\t\tadvance(&id)\n\t}\n}\n"), findings: 1, loopCalls: 1},
		{name: "counter varies object", source: change("u.once(ctx, id)", "u.once(ctx, ids[attempt])"), findings: 1, loopCalls: 1},
		{name: "cap shadowed by parameter", source: change("id string)", "id string, retryLimit int)"), findings: 1, loopCalls: 1},
		{name: "errors alias shadowed", source: change("id string)", "id string, stderrors fakeErrors)"), findings: 1, loopCalls: 1},
		{name: "sentinel alias shadowed", source: change("id string)", "id string, iamerr fakeErrors)"), findings: 1, loopCalls: 1},
		{name: "extra question in backoff", source: change("\t}\n}\n", "\t\t_, _ = u.once(ctx, id)\n\t}\n}\n"), findings: 2, loopCalls: 2},
		{name: "nested page loop retains question", source: change("\t}\n}\n", "\t\tfor _, other := range ids { _, _ = u.once(ctx, other) }\n\t}\n}\n"), findings: 2, loopCalls: 2},
		{name: "same callee in another page stays visible", source: retryGateFixture + pageMethod, findings: 1, cleared: 1, loopCalls: 2},
		{name: "retry nested inside page", source: change("\tfor attempt := 1; ; attempt++ {", "\tfor _, id := range ids {\n\tfor attempt := 1; ; attempt++ {") + "}\n", findings: 1, loopCalls: 1},
		{name: "callee page remains visible", source: retryGateFixture,
			staged:   strings.Replace(retryGateStagedFixture, "\treturn \"\", nil", "\tfor _, other := range ids { _, _ = u.stage(ctx, other) }\n\treturn \"\", nil", 1),
			findings: 1, cleared: 1, loopCalls: 2},
		{name: "transaction spelling is no exemption", source: strings.ReplaceAll(retryGateFixture+pageMethod, "once", "deleteOnce"),
			staged: strings.ReplaceAll(retryGateStagedFixture, "once", "deleteOnce"), findings: 1, cleared: 1, loopCalls: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			staged := tc.staged
			if staged == "" {
				staged = retryGateStagedFixture
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, "attempt.go"), []byte(tc.source), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "staged.go"), []byte(staged), 0o600))
			scan := scanForPerRowRelationQuestions(t, dir, relationQuestionEntryPoints)
			require.Equal(t, 2, scan.filesParsed)
			require.GreaterOrEqual(t, scan.localWrappersResolved, 3, "hidden staged recheck must remain resolved")
			require.GreaterOrEqual(t, scan.callsSeen, 3, "a quiet scanner is not a positive control")
			require.Equal(t, tc.loopCalls, scan.callsInLoop)
			require.Equal(t, tc.cleared, scan.callsInBoundedRetry)
			require.Len(t, scan.boundedRetrySites, tc.cleared)
			require.Len(t, scan.findings, tc.findings)
		})
	}
}

// Реальные packages несут confounders: одноимённые методы других receivers,
// staged callbacks и legacy ветви. Копируем весь плоский package source и меняем
// только контролируемый retry fragment; авторизационный recheck не удаляем.
func TestBoundedRetryGateOnRealStagedOperationSources(t *testing.T) {
	for _, site := range []struct {
		dir, file, callee, cap, success string
	}{
		{"access_binding", "delete.go", "deleteOnce", "deleteAttempts", "return anypb.New(&emptypb.Empty{})"},
		{"grant_delegation", "revoke.go", "revokeOnce", "revokeAttempts", "return marshalGD(revoked)"},
	} {
		t.Run(site.dir, func(t *testing.T) {
			root := filepath.Join(useCaseTreeRoot, site.dir)
			entries, err := os.ReadDir(root)
			require.NoError(t, err)
			sources := map[string][]byte{}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(root, entry.Name()))
				require.NoError(t, err)
				sources[entry.Name()] = data
			}
			require.Contains(t, sources, site.file)
			for _, mutation := range []struct {
				name, old, replacement string
			}{
				{name: "actual staged retry"},
				{"cap removed", " || attempt == " + site.cap, ""},
				{"wrong retry failure", "!stderrors.Is(err, iamerr.ErrAborted) || attempt == " + site.cap, "!stderrors.Is(err, iamerr.ErrUnavailable) || attempt == " + site.cap},
				{"success repeats", site.success, "continue"},
				{"four attempts", "const " + site.cap + " = 3", "const " + site.cap + " = 4"},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					dir := t.TempDir()
					for name, original := range sources {
						data := string(original)
						if name == site.file && mutation.old != "" {
							require.Equal(t, 1, strings.Count(data, mutation.old), "real injection anchor must remain unique")
							data = strings.Replace(data, mutation.old, mutation.replacement, 1)
						}
						require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600))
					}
					scan := scanForPerRowRelationQuestions(t, dir, relationQuestionEntryPoints)
					key := filepath.ToSlash(filepath.Join(dir, site.file)) + ": " + site.callee
					flagged := false
					for _, finding := range scan.findings {
						flagged = flagged || finding.key == key
					}
					require.Equal(t, len(sources), scan.filesParsed)
					require.NotZero(t, scan.localWrappersResolved)
					if mutation.old == "" {
						require.Contains(t, scan.boundedRetrySites, key, "actual staged retry must be recognised, not lost")
						require.False(t, flagged)
					} else {
						require.NotContains(t, scan.boundedRetrySites, key)
						require.True(t, flagged, "unsafe mutation must remain a relation question and turn the gate red")
					}
				})
			}
		})
	}
}
