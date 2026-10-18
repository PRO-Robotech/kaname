// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// revision_test.go — сценарий 865-17 приёмки
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`
// (kaname#865): форма значения ключа `revision`.
//
// Документ — фикстура `probemod.public-read-fixture.yaml` (P11), в которую
// `publicreadfixture.WithRevisionText` (P14) вписал значение ТЕКСТОМ: проба
// судит загрузчик на том, что пишет автор, а не на собранной структуре.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// revisionDoc — R(1, true) с текстом значения `revision`, заменённым на text.
func revisionDoc(t *testing.T, text string) []byte {
	t.Helper()
	base, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err)
	r1, err := publicreadfixture.WithRevision(base, 1)
	require.NoError(t, err)
	doc, err := publicreadfixture.WithRevisionText(r1, text)
	require.NoError(t, err)
	return doc
}

// Test865_17_RevisionValueForm — отказы формы значения и их близнецы.
//
// Каждый близнец отличается от своего отрицания ровно записью значения:
// `5.0`, `"5"` и `+5` — от `5`; `010` — от `8`; `0x10` — от `16`; `1e3` — от
// `1000`; предел — от `9223372036854775807`.
func Test865_17_RevisionValueForm(t *testing.T) {
	notPositive := []string{"0", "-1", "010", "0x10", "+5"}
	for _, text := range notPositive {
		t.Run("not-positive/"+text, func(t *testing.T) {
			m, err := manifest.Load(revisionDoc(t, text))
			require.Nil(t, m, "отвергнутый документ не возвращается")
			require.Error(t, err)
			require.Equal(t, "manifest: revision must be a positive integer, got "+text, err.Error())
			require.True(t, errors.Is(err, manifest.ErrRevisionNotPositive), "%v", err)
		})
	}

	shape := []string{`"5"`, "1.5", "5.0", "1e3", "9223372036854775808"}
	for _, text := range shape {
		t.Run("shape/"+text, func(t *testing.T) {
			m, err := manifest.Load(revisionDoc(t, text))
			require.Nil(t, m, "отвергнутый документ не возвращается")
			require.Error(t, err)
			require.True(t, errors.Is(err, manifest.ErrShape), "ожидался ErrShape: %v", err)
		})
	}

	twins := map[string]int64{
		"1":                   1,
		"5":                   5,
		"8":                   8,
		"16":                  16,
		"1000":                1000,
		"9223372036854775807": 9223372036854775807,
	}
	for text, want := range twins {
		t.Run("twin/"+text, func(t *testing.T) {
			m, err := manifest.Load(revisionDoc(t, text))
			require.NoError(t, err)
			got, declared := m.Revision()
			require.True(t, declared, "редакция объявлена")
			require.Equal(t, want, got)
		})
	}
}

// Test865_17_RevisionDeclarednessIsJudgedOnTheNode — строки разбора условий
// CE-01: объявленность судится по узлу документа, пустое значение и `~` —
// отказ формы, недесятичная запись целого — отказ положительности, псевдоним
// разворачивается ДО проверки тега.
func Test865_17_RevisionDeclarednessIsJudgedOnTheNode(t *testing.T) {
	t.Run("null", func(t *testing.T) {
		for _, text := range []string{"~", ""} {
			m, err := manifest.Load(revisionDoc(t, text))
			require.Nil(t, m)
			require.True(t, errors.Is(err, manifest.ErrShape), "%q: %v", text, err)
		}
	})
	t.Run("non-decimal-int", func(t *testing.T) {
		// `1_000` разборщик помечает тегом !!int (знак подчёркивания он
		// снимает при чтении числа), поэтому отказ — положительности, а не формы.
		for _, text := range []string{"0o10", "0b10", "-0", "1_000"} {
			m, err := manifest.Load(revisionDoc(t, text))
			require.Nil(t, m)
			require.Error(t, err)
			require.Equal(t, "manifest: revision must be a positive integer, got "+text, err.Error())
		}
	})
	t.Run("alias", func(t *testing.T) {
		// Якорь на имени модуля (тег !!str), псевдоним — значение редакции:
		// отказ обязан назвать тег УЗЛА ЯКОРЯ, а не вид «псевдоним».
		base := revisionDoc(t, "*p")
		doc := []byte(replaceOnceT(t, string(base), "module: probemod", "module: &p probemod"))
		m, err := manifest.Load(doc)
		require.Nil(t, m)
		require.True(t, errors.Is(err, manifest.ErrShape), "%v", err)
		require.Contains(t, err.Error(), "!!str")
	})
	t.Run("absent", func(t *testing.T) {
		base, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
		require.NoError(t, err)
		m, err := manifest.Load(base)
		require.NoError(t, err)
		n, declared := m.Revision()
		require.False(t, declared, "ключа нет — редакция не объявлена")
		require.Zero(t, n)
	})
}

func replaceOnceT(t *testing.T, s, old, repl string) string {
	t.Helper()
	i := indexOnce(s, old)
	require.GreaterOrEqual(t, i, 0, "строка %q обязана встретиться ровно один раз", old)
	return s[:i] + repl + s[i+len(old):]
}

func indexOnce(s, sub string) int {
	first := -1
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			if first >= 0 {
				return -1
			}
			first = i
		}
	}
	return first
}
