// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// client_description_test.go — приведение описания клиента (приёмка
// `own-sessions-are-listed-and-ended-by-their-owner.md`, Р3; держатель
// сценария OS-04 (г), (д) на уровне типа): замена байтов вне UTF-8 — по руне
// U+FFFD на КАЖДЫЙ байт, затем урезание до 512 рун; пустое — отсутствие.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestOS04_ClientDescriptionNormalization(t *testing.T) {
	cases := []struct {
		label, raw, want string
		absent           bool
	}{
		{"(а) как прислано", "Mozilla/5.0 (X11; Linux x86_64) os-04", "Mozilla/5.0 (X11; Linux x86_64) os-04", false},
		{"(б) 600 знаков — 512", strings.Repeat("x", 600), strings.Repeat("x", 512), false},
		{"(в) пусто — отсутствие", "", "", true},
		{"(г) два байта вне UTF-8 — две руны U+FFFD", "os-04-\xff\xfe-end", "os-04-��-end", false},
		{"(д) 600 рун «ж» — 512 рун, 1024 байта", strings.Repeat("ж", 600), strings.Repeat("ж", 512), false},
		{"512 рун — без урезания (граница)", strings.Repeat("ж", 512), strings.Repeat("ж", 512), false},
		{"замена до урезания: 600 байт 0xFF — 512 рун U+FFFD", strings.Repeat("\xff", 600), strings.Repeat("�", 512), false},
		{"оборванная многобайтовая последовательность — по руне на байт", "a\xd0", "a�", false},
	}
	for _, c := range cases {
		d := domain.NewClientDescription(c.raw)
		require.Equal(t, c.absent, d.IsZero(), "%s: отсутствие", c.label)
		require.Equal(t, c.want, d.Value(), "%s: значение", c.label)
		require.True(t, utf8.ValidString(d.Value()), "%s: допустимый UTF-8", c.label)
		require.LessOrEqual(t, utf8.RuneCountInString(d.Value()), domain.ClientDescriptionMaxRunes, "%s: не длиннее 512 рун", c.label)
		// Приведение идемпотентно: прочитанное из записи значение приводится в себя.
		require.Equal(t, d, domain.NewClientDescription(d.Value()), "%s: приведение идемпотентно", c.label)
	}
}
