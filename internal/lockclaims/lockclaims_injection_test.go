// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lockclaims_injection_test.go — проверка СПОСОБНА упасть и способна смолчать.
//
// Инъекция подаёт настоящий вход синтетическим деревом и требует контроля в ОБЕ
// стороны по каждой оси:
//
//	ось          находка                          законный близнец
//	───────────  ───────────────────────────────  ──────────────────────────────
//	форма        оборот без отрицания в окне      он же с отрицанием в окне
//	носитель     оборот в КОММЕНТАРИИ             он же в строковом литерале
//	предпосылка  вызов AcquireBindingLock         то же имя в комментарии
//	объём        дерево с предметом               дерево БЕЗ предмета → перепись 0
//
// Сами обороты стоят в фикстурах НИЖЕ, строковыми константами, и в прозе этого
// файла не воспроизводятся: комментарий, цитирующий утверждение, сам стал бы
// находкой.
//
// Без второй колонки проверка ловила бы форму, а не существо: первый же ложный
// срабат её отключит.
package lockclaims

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// syntheticTree — синтетическое дерево из пар «путь → содержимое».
func syntheticTree(t *testing.T, files map[string]string) *treecorpus.Tree {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o600))
	}
	tree, err := treecorpus.SyntheticTree(root)
	require.NoError(t, err)
	return tree
}

const claimSource = `package sample

// Materialize делает форвард.
//
// Materialize materializes the object's tuples across the matching bindings under
// a SHARE advisory lock (no EXCLUSIVE / O(scope) recompute).
func Materialize() {}
`

const denialSource = `package sample

// Materialize делает форвард.
//
// Materialize materializes the object's tuples across the matching bindings and
// holds no SHARE advisory lock while doing so — the lock was removed.
func Materialize() {}
`

const literalSource = `package sample

// Materialize делает форвард; оборот ниже живёт в СТРОКЕ, а не в утверждении.
func Materialize() string {
	const advisoryLockPhrase = "under a SHARE advisory lock (no EXCLUSIVE)"
	return advisoryLockPhrase
}
`

const cleanSource = `package sample

// Materialize делает форвард без единого упоминания предмета.
func Materialize() {}
`

// TestGateFindsTheClaimAndStaysSilentOnItsLegitimateTwin — ось «форма».
func TestGateFindsTheClaimAndStaysSilentOnItsLegitimateTwin(t *testing.T) {
	t.Run("находка: оборот без отрицания", func(t *testing.T) {
		census, findings, err := scanLockClaims(syntheticTree(t, map[string]string{"pkg/sample.go": claimSource}))
		require.NoError(t, err)
		require.Len(t, findings, 1, "утверждение о SHARE-блокировке обязано быть найдено")
		require.Equal(t, "pkg/sample.go", findings[0].file, "находка обязана НАЗЫВАТЬ координату")
		require.NotZero(t, findings[0].line, "находка обязана называть строку")
		require.Contains(t, findings[0].excerpt, "SHARE advisory lock",
			"находка обязана показывать сам оборот, а не только факт")
		require.Equal(t, 1, census.claims)
		require.Zero(t, census.denials)
	})

	t.Run("законный близнец: тот же оборот с отрицанием — молчание", func(t *testing.T) {
		census, findings, err := scanLockClaims(syntheticTree(t, map[string]string{"pkg/sample.go": denialSource}))
		require.NoError(t, err)
		require.Emptyf(t, findings, "отрицание блокировки — законная форма и находкой не является: %v", findings)
		require.Equal(t, 1, census.denials, "отрицание обязано быть СОСЧИТАНО, а не просто пропущено")
		require.Zero(t, census.claims)
	})

	t.Run("носитель: оборот в строковом литерале утверждением не является", func(t *testing.T) {
		census, findings, err := scanLockClaims(syntheticTree(t, map[string]string{"pkg/sample.go": literalSource}))
		require.NoError(t, err)
		require.Empty(t, findings,
			"оборот в СТРОКЕ — не утверждение о поведении; иначе проверка нашла бы находкой саму себя")
		require.Zero(t, census.claims)
		require.NotZero(t, census.commentGroups, "комментарии этого файла всё равно обязаны быть прочитаны")
	})

	t.Run("объём: дерево без предмета даёт перепись 0, а не тишину", func(t *testing.T) {
		census, findings, err := scanLockClaims(syntheticTree(t, map[string]string{"pkg/sample.go": cleanSource}))
		require.NoError(t, err)
		require.Empty(t, findings)
		require.Equal(t, 1, census.filesParsed)
		require.Zero(t, census.advisoryMentions,
			"на дереве без предмета перепись обязана печатать ноль — именно её ноль роняет гейт "+
				"как «ноль прочитанного», а не «ноль находок»")
	})
}

// TestPremiseDerivationJudgesTheCallNodeNotTheWord — ось «предпосылка».
func TestPremiseDerivationJudgesTheCallNodeNotTheWord(t *testing.T) {
	root := t.TempDir()

	takes := filepath.Join(root, "takes.go")
	require.NoError(t, os.WriteFile(takes, []byte(`package sample

func Run(s Store) error { return s.AcquireBindingLock(nil, "b") }

type Store interface{ AcquireBindingLock(ctx any, id string) error }
`), 0o600))

	mentions := filepath.Join(root, "mentions.go")
	require.NoError(t, os.WriteFile(mentions, []byte(`package sample

// Run НЕ берёт блокировки: AcquireBindingLock зовёт только полный проход.
func Run() error { return nil }
`), 0o600))

	n, err := lockAcquireCalls(takes)
	require.NoError(t, err)
	require.Equalf(t, 1, n,
		"положительный контроль: вызов захвата обязан быть найден — иначе «ноль у форварда» "+
			"ничего не доказывает")

	n, err = lockAcquireCalls(mentions)
	require.NoError(t, err)
	require.Zerof(t, n,
		"законный близнец: имя захвата в КОММЕНТАРИИ вызовом не является; счёт по слову дал бы "+
			"блокировку там, где её нет, и перевернул бы предпосылку гейта")
}
