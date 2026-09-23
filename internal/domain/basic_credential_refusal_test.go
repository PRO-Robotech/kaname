// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_refusal_test.go — причина единого отказа полосы базового
// секрета едет ВНУТРЬ и не меняет того, что видно снаружи (задача kaname#379).
//
// Утверждается три вещи, и каждая — про значение ошибки, а не про её
// производителя:
//
//   - отказ с любой причиной остаётся единым отказом: `errors.Is` истинно, текст
//     дословно равен тексту сторожевого — вызывающий, напечатавший ошибку,
//     различия не увидит;
//   - причина читается обратно ровно той, какой была названа, в том числе
//     сквозь обёртку `%w`;
//   - голый сторожевой и посторонняя ошибка причины НЕ несут — «причина не
//     названа» отличимо от любой названной.
package domain_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestBasicCredentialRefusal_ReasonTravelsInwardAndTheTextStaysOne — отказ с
// причиной есть тот же единый отказ, а причина читается обратно.
func TestBasicCredentialRefusal_ReasonTravelsInwardAndTheTextStaysOne(t *testing.T) {
	reasons := domain.BasicCredentialRefusalReasons()

	// Предпосылка: словарь несёт три причины, которые обязаны различаться
	// внутри, — отсечку отзыва-всех, отсутствие строки и неверный секрет.
	// Словарь, не назвавший хотя бы одну, сделал бы пробу ниже беспредметной.
	seen := map[domain.BasicCredentialRefusalReason]bool{}
	for _, r := range reasons {
		require.Falsef(t, seen[r], "причина %q объявлена в словаре дважды", r)
		seen[r] = true
	}
	for _, must := range []domain.BasicCredentialRefusalReason{
		domain.BasicRefusalOwnerRevoked, domain.BasicRefusalNotFound, domain.BasicRefusalSecretMismatch,
	} {
		require.Truef(t, seen[must], "словарь причин не называет %q — различать её внутри нечем", must)
	}

	var checked int
	for _, reason := range reasons {
		err := domain.RefuseBasicCredential(reason)
		require.Truef(t, errors.Is(err, domain.ErrBasicCredentialRefused),
			"отказ с причиной %q перестал быть единым отказом полосы", reason)
		require.Equalf(t, domain.ErrBasicCredentialRefused.Error(), err.Error(),
			"текст отказа с причиной %q отличается от единого — по нему узнали бы причину", reason)

		got, ok := domain.BasicCredentialRefusalReasonOf(err)
		require.Truef(t, ok, "причина %q названа и не читается обратно", reason)
		require.Equal(t, reason, got)

		// Сквозь обёртку вызывающего причина доезжает той же.
		wrapped := fmt.Errorf("lane: %w", err)
		got, ok = domain.BasicCredentialRefusalReasonOf(wrapped)
		require.Truef(t, ok, "причина %q теряется в обёртке %%w", reason)
		require.Equal(t, reason, got)
		checked++
	}
	t.Logf("перепись: причин в словаре %d · проверено %d", len(reasons), checked)
	require.Equal(t, len(reasons), checked)
}

// TestBasicCredentialRefusal_BareSentinelNamesNoReason — голый сторожевой и
// посторонняя ошибка причины не несут: «не названа» — свой исход.
func TestBasicCredentialRefusal_BareSentinelNamesNoReason(t *testing.T) {
	for name, err := range map[string]error{
		"голый сторожевой":     domain.ErrBasicCredentialRefused,
		"сторожевой в обёртке": fmt.Errorf("lane: %w", domain.ErrBasicCredentialRefused),
		"посторонняя ошибка":   errors.New("connection reset"),
		"отсутствие ошибки":    nil,
	} {
		reason, ok := domain.BasicCredentialRefusalReasonOf(err)
		require.Falsef(t, ok, "%s: прочитана причина %q, которой никто не называл", name, reason)
		require.Emptyf(t, reason, "%s: причины нет, а значение непусто", name)
	}
}
