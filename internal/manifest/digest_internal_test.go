// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// digest_internal_test.go — сценарий 865-26 приёмки
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`
// (kaname#865): каноническая форма документа и его отпечаток (Д9), и
// модульная половина 865-32.
//
// Пункты 1–3 судят функцию отпечатка над деревом узлов БЕЗ загрузчика; пункты
// 4–6 — через `Load`, то есть отпечаток, который отдаёт разобранный манифест.

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

var digestShape = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// formOf — каноническая форма и отпечаток документа, построенные над деревом
// узлов `yaml.v3` без загрузчика.
func formOf(t *testing.T, doc string) (string, string) {
	t.Helper()
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(doc), &root), "документ %q", doc)
	form, err := canonicalForm(&root)
	require.NoError(t, err, "форма %q", doc)
	d, err := digestOfNode(&root)
	require.NoError(t, err, "отпечаток %q", doc)
	require.Regexp(t, digestShape, d)
	return form, d
}

// Test865_26_CanonicalFormAndDigest — пункты 1, 2, 2а и 3.
func Test865_26_CanonicalFormAndDigest(t *testing.T) {
	const ref = "b: [2, 1]\na: \"x\"  # комментарий\n"
	form, d := formOf(t, ref)

	// П.1 — опорное значение. Ожидаемый отпечаток сверен НЕЗАВИСИМО: SHA-256
	// стандартной библиотеки над объявленной строкой формы, а не над выходом
	// проверяемой функции.
	const wantForm = `{"a":"!!str x","b":["!!int 2","!!int 1"]}`
	require.Equal(t, wantForm, form)
	require.Equal(t, "sha256:0d437a49bbc37a7eb402941e4b0661e36808c9f0c3199a8280df7cb5bf4f1767", d)
	require.Equal(t, fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(wantForm))), d)

	// П.2 — равны опорному: порядок ключей, кавычки, комментарий, блочная
	// запись, якорь без ссылки.
	for _, same := range []string{
		"a: x\nb: [2, 1]\n",
		"a: 'x'\nb:\n  - 2\n  - 1\n",
		"a: &s \"x\"\nb: [2, 1]\n",
	} {
		_, got := formOf(t, same)
		require.Equal(t, d, got, "документ %q обязан дать опорный отпечаток", same)
	}

	// П.2а — псевдоним развёрнут.
	_, p1 := formOf(t, "p: &n [2, 1]\nq: *n\n")
	_, p2 := formOf(t, "p: [2, 1]\nq: [2, 1]\n")
	require.Equal(t, p2, p1, "псевдоним обязан давать форму узла своего якоря")

	// П.3 — каждый отличается от опорного ровно одним фактом.
	for _, other := range []string{
		"a: x\nb: [1, 2]\n",       // порядок последовательности
		"a: y\nb: [2, 1]\n",       // значение строки
		"a: \"x\"\nb: [0x2, 1]\n", // текст целого
		"a: x\nb: [2.0, 1]\n",     // тег скаляра
	} {
		_, got := formOf(t, other)
		require.NotEqual(t, d, got, "документ %q обязан дать иной отпечаток", other)
	}
	_, a5 := formOf(t, "a: 5\n")
	_, a5s := formOf(t, "a: \"5\"\n")
	require.NotEqual(t, a5, a5s, "строка \"5\" и целое 5 различны по тегу")
}

// Test865_26_FormEscapesLikeJCS — строка JCS (RFC 8785 §3.2.2.2): экранируются
// только кавычка, обратная косая и управляющие знаки; `<>&`, U+2028 и U+2029
// остаются как есть, а ключи упорядочены по кодовым единицам UTF-16, а не по
// байтам UTF-8 (условие CE-03).
func Test865_26_FormEscapesLikeJCS(t *testing.T) {
	form, _ := formOf(t, "a: \"<>&\\u2028\\u2029\\t\\u0001\\\"\\\\\"\n")
	require.Equal(t, "{\"a\":\"!!str <>&  \\t\\u0001\\\"\\\\\"}", form)

	// По байтам UTF-8 U+FF61 (0xEF…) идёт раньше U+1F600 (0xF0…), а по
	// кодовым единицам UTF-16 — позже: U+1F600 есть суррогатная пара 0xD83D…,
	// и 0xD83D < 0xFF61. Порядок по UTF-16 ставит U+1F600 первым.
	form, _ = formOf(t, "\"｡\": 1\n\"\U0001F600\": 2\n")
	require.Equal(t, "{\"\U0001F600\":\"!!int 2\",\"｡\":\"!!int 1\"}", form)
}

// Test865_26_AliasCycleIsRefused — якорь, содержащий себя: форма не строится,
// а не уходит в бесконечную рекурсию.
func Test865_26_AliasCycleIsRefused(t *testing.T) {
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("a: &x [*x]\n"), &root))
	_, err := canonicalForm(&root)
	require.Error(t, err)
}

// probemodRevision — R(n, open) фикстуры P11 с редакцией n.
func probemodRevision(t *testing.T, n int64, open bool) []byte {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err)
	if !open {
		doc, err = publicreadfixture.WithoutKey(doc)
		require.NoError(t, err)
	}
	doc, err = publicreadfixture.WithRevision(doc, n)
	require.NoError(t, err)
	return doc
}

// loadedForm — каноническая форма и отпечаток принятого загрузчиком документа.
func loadedForm(t *testing.T, doc []byte) (string, string) {
	t.Helper()
	m, err := Load(doc)
	require.NoError(t, err)
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(doc, &root))
	form, err := canonicalForm(&root)
	require.NoError(t, err)
	require.Regexp(t, digestShape, m.Digest())
	return form, m.Digest()
}

// Test865_26_DigestThroughLoad — пункты 4, 5 и 6.
func Test865_26_DigestThroughLoad(t *testing.T) {
	// П.4 — предел редакции входит в форму текстом.
	form, _ := loadedForm(t, probemodRevision(t, 9223372036854775807, true))
	require.Contains(t, form, `"revision":"!!int 9223372036854775807"`)

	// П.5 — содержимое различает, запись — нет.
	_, dOpen := loadedForm(t, probemodRevision(t, 5, true))
	_, dClosed := loadedForm(t, probemodRevision(t, 5, false))
	require.NotEqual(t, dOpen, dClosed)
	reformatted, err := publicreadfixture.Reformatted(probemodRevision(t, 5, true))
	require.NoError(t, err)
	require.NotEqual(t, string(probemodRevision(t, 5, true)), string(reformatted), "переформатирование обязано менять байты")
	_, dRef := loadedForm(t, reformatted)
	require.Equal(t, dOpen, dRef, "переформатированный документ обязан дать тот же отпечаток")

	// П.6 — форма определена для каждого принятого документа.
	cases := []struct{ text, desc, inForm string }{
		{".nan", ".nan", `"description":"!!float .nan"`},
		{".inf", ".inf", `"description":"!!float .inf"`},
		{"-.inf", "-.inf", `"description":"!!float -.inf"`},
		{"1.0", "1.0", `"description":"!!float 1.0"`},
		{"2001-12-14", "2001-12-14", `"description":"!!timestamp 2001-12-14"`},
		{"true", "true", `"description":"!!bool true"`},
		{"!!binary aGk=", "hi", `"description":"!!binary aGk="`},
		{"!foo bar", "bar", `"description":"!foo bar"`},
	}
	for _, c := range cases {
		doc, err := publicreadfixture.WithRoles(probemodRevision(t, 5, true), c.text)
		require.NoError(t, err)
		m, err := Load(doc)
		require.NoError(t, err, "описание %q", c.text)
		require.Len(t, m.Roles, 1)
		require.Equal(t, c.desc, m.Roles[0].Description, "описание %q", c.text)
		form, d := loadedForm(t, doc)
		require.Contains(t, form, c.inForm)
		require.Regexp(t, digestShape, d)
	}
}

// Test865_32_ScalarTextOfAStringFieldEntersTheDigest — модульная половина
// 865-32: `16` и `0x10` в строковом поле загрузчик читает в разные описания,
// и отпечатки различны; переформатирование того же документа — равен.
func Test865_32_ScalarTextOfAStringFieldEntersTheDigest(t *testing.T) {
	q := func(desc string) []byte {
		doc, err := publicreadfixture.WithRoles(probemodRevision(t, 5, true), desc)
		require.NoError(t, err)
		return doc
	}
	m16, err := Load(q("16"))
	require.NoError(t, err)
	m0x, err := Load(q("0x10"))
	require.NoError(t, err)
	require.Equal(t, "16", m16.Roles[0].Description)
	require.Equal(t, "0x10", m0x.Roles[0].Description)
	require.NotEqual(t, m16.Digest(), m0x.Digest())

	ref, err := publicreadfixture.Reformatted(q("16"))
	require.NoError(t, err)
	mRef, err := Load(ref)
	require.NoError(t, err)
	require.Equal(t, m16.Digest(), mRef.Digest())
	require.True(t, strings.HasPrefix(m16.Digest(), "sha256:"))
}
