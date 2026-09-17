// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// authz_page_device_condition_test.go — Ф7-32 (задача PRO-Robotech/kacho#1273,
// приёмка `access-keys-are-ours.md` §1.8, Р4): ни одна строка таблицы условий
// публичной страницы не обещает арендатору проверки АТТЕСТАЦИИ КЛЮЧА.
//
// Строка `device_compliant` описывала согласие устройства как сверку модели
// ключа (AAGUID) со списком одобренных — ровно ту проверку, которую Р4 решает
// не строить (аттестация не требуется, не проверяется и не хранится). Второй
// носитель того же обещания — деривация значения токена — снят Ф7-39.
//
// Перепись печатает ОБЕ величины: строк таблицы N · из них обещающих проверку
// аттестации ключа M — до Ф7 `6 · 1`, после `6 · 0`. Одна величина скрыла бы,
// снята ли строка или таблица целиком: положительный контроль — соседние пять
// строк и само объявление условия в каноне не тронуты.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	authzPageRel      = "docs/content/architecture/authz.mdx"
	authzModelRel     = "internal/authzmodel/fga_model.fga"
	conditionsTableHd = "<thead><tr><th>Условие</th>"
)

var (
	reConditionRow    = regexp.MustCompile(`<tr><td><code>([a-z&#0-9;_]+)</code></td><td>(.*?)</td></tr>`)
	reAttestationWord = regexp.MustCompile(`(?i)attestation|аттестац|AAGUID`)
	reModelCondition  = regexp.MustCompile(`(?m)^condition ([a-z_]+)`)
)

// conditionsTableRows — строки таблицы условий: имя (с развёрнутым `&#95;`) и текст.
func conditionsTableRows(page string) (rows [][2]string) {
	start := strings.Index(page, conditionsTableHd)
	if start < 0 {
		return nil
	}
	end := strings.Index(page[start:], "</tbody>")
	if end < 0 {
		return nil
	}
	for _, m := range reConditionRow.FindAllStringSubmatch(page[start:start+end], -1) {
		rows = append(rows, [2]string{strings.ReplaceAll(m[1], "&#95;", "_"), m[2]})
	}
	return rows
}

func TestAccessKey_F7_32_NoConditionRowPromisesKeyAttestation(t *testing.T) {
	root := moduleRoot(t)
	page, err := os.ReadFile(filepath.Join(root, authzPageRel))
	require.NoError(t, err)
	model, err := os.ReadFile(filepath.Join(root, authzModelRel))
	require.NoError(t, err)

	rows := conditionsTableRows(string(page))
	require.NotEmpty(t, rows, "таблица условий на странице не найдена — обход беспредметен")
	declared := reModelCondition.FindAllStringSubmatch(string(model), -1)
	require.NotEmpty(t, declared, "объявлений условий в каноне не прочитано — обход беспредметен")

	var promising []string
	names := map[string]bool{}
	for _, r := range rows {
		names[r[0]] = true
		if reAttestationWord.MatchString(r[1]) {
			promising = append(promising, r[0]+": "+r[1])
		}
	}
	t.Logf("перепись: строк таблицы условий %d · из них обещающих проверку аттестации ключа %d · объявлений условий в каноне %d",
		len(rows), len(promising), len(declared))

	// Положительный контроль: таблица и канон на месте, строка у каждого
	// объявленного условия есть — снята ФОРМУЛИРОВКА, а не строка и не таблица.
	require.Len(t, rows, len(declared), "строк таблицы столько же, сколько объявлений условий в каноне")
	for _, d := range declared {
		require.True(t, names[d[1]], "условие %s объявлено каноном, а строки на странице нет", d[1])
	}
	require.True(t, names["device_compliant"], "строка условия согласия устройства обязана остаться")
	require.Empty(t, promising, "строка таблицы условий обещает проверку аттестации ключа, которой продукт не делает (Р4)")
}

// TestAccessKey_F7_32_ProbeSeesThePromise — инъекция: строка прежней
// формулировки находится, соседняя законная — нет.
func TestAccessKey_F7_32_ProbeSeesThePromise(t *testing.T) {
	page := conditionsTableHd + `<th>Семантика</th></tr></thead>
  <tbody>
    <tr><td><code>jit&#95;window</code></td><td>Разрешено в течение <code>ttl&#95;seconds</code> после активации</td></tr>
    <tr><td><code>device&#95;compliant</code></td><td>WebAuthn device-attestation в списке одобренных AAGUID</td></tr>
  </tbody>`
	rows := conditionsTableRows(page)
	require.Len(t, rows, 2)
	require.Equal(t, "device_compliant", rows[1][0])
	require.True(t, reAttestationWord.MatchString(rows[1][1]))
	require.False(t, reAttestationWord.MatchString(rows[0][1]))
}
