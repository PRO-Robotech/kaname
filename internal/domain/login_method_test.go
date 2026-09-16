// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_method_test.go — доменные типы способа входа человека (фаза Ф2,
// задача `kacho#1268`; F4d-13, форма строки — держится частично, см. шапку
// `login_method.go`).
//
// Предмет проб — два свойства, которые держит ТИП, а не дисциплина вызывающего:
//
//  1. пустого значения не бывает — ни вида способа, ни проверочного материала:
//     «материала нет» выражается ОТСУТСТВИЕМ строки, а не пустой строкой в ней;
//  2. материал не уезжает из процесса ни одним общим путём печати и
//     сериализации — ни форматированием, ни журналом, ни JSON. Выход у него
//     один, названный (`Reveal`), и его вызывающих держит гейт дерева
//     `internal/check` `TestLoginVerifierStaysInside`.
//
// Каждое отрицание стоит рядом с положительным контролем: «материал не
// напечатан» верно и о значении, которое не несёт материала вовсе.
package domain_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// probeMaterial — значение, которое ОБЯЗАНО выглядеть чужим: по нему ищется
// утечка, и совпасть с чем-либо законным в выводе оно не может.
const probeMaterial = "$2a$12$PROBE.login.verifier.f2p1.must.not.leak.anywhere"

func TestLoginMethodKind_DictionaryIsClosed(t *testing.T) {
	kinds := domain.LoginMethodKinds()
	require.NotEmpty(t, kinds, "словарь видов пуст — «закрыт» здесь означало бы «видов нет»")

	for _, k := range kinds {
		got, err := domain.ParseLoginMethodKind(string(k))
		require.NoError(t, err, "вид %q из словаря обязан разбираться", k)
		require.Equal(t, k, got)
		require.NoError(t, k.Validate())
	}
	t.Logf("перепись: видов в словаре %d — %v", len(kinds), kinds)

	// Вне словаря — отказ, называющий поле и допустимое. Регистр не
	// нормализуется: написание одно, иначе вид становится двумя значениями.
	for _, bad := range []string{"", "Password", "PASSWORD", "totp", "otp", "password ", "sms"} {
		_, err := domain.ParseLoginMethodKind(bad)
		require.Error(t, err, "вид %q обязан быть отвергнут", bad)
		require.Contains(t, err.Error(), "Illegal argument login_method.kind",
			"отказ обязан называть поле, иначе он не восстанавливает следующий шаг")
		require.Contains(t, err.Error(), "password", "отказ обязан называть допустимое")
	}
}

func TestLoginVerifier_EmptyIsRefused(t *testing.T) {
	_, err := domain.NewLoginVerifier("")
	require.Error(t, err, "пустой материал обязан быть отвергнут типом, а не дойти до базы")
	require.Contains(t, err.Error(), "Illegal argument login_method.verifier: required")

	var zero domain.LoginVerifier
	require.True(t, zero.IsZero(), "нулевое значение типа обязано читаться как «материала нет»")

	// Положительный контроль: непустое проходит, и материал выдаётся ДОСЛОВНО —
	// без обрезки и нормализации. Перенос прежних хешей (Р1 Ф1) держится ровно
	// на этом: переписанный хеш перестаёт совпадать с паролем.
	for _, material := range []string{
		probeMaterial,
		" " + probeMaterial + " ", // пробелы по краям — часть значения, а не мусор
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"Ω-материал-не-ascii",
	} {
		v, err := domain.NewLoginVerifier(material)
		require.NoError(t, err)
		require.False(t, v.IsZero())
		require.Equal(t, material, v.Reveal(), "материал обязан выдаваться побайтово тем, что положили")
	}
}

// TestLoginVerifier_NeverPrinted — ни один общий путь печати не несёт материал.
func TestLoginVerifier_NeverPrinted(t *testing.T) {
	v, err := domain.NewLoginVerifier(probeMaterial)
	require.NoError(t, err)
	m := domain.LoginMethod{UserID: "usr0000000000000lm01", Kind: domain.LoginMethodPassword, Verifier: v}

	// Держатель в НЕэкспортированном поле: `fmt` обходит такие поля без вызова
	// методов, то есть форматирование типа здесь НЕ срабатывает. Утечку тогда
	// предотвращает только устройство типа (материал за указателем) — эта
	// строка и есть проверка устройства, а не метода.
	type holder struct{ m domain.LoginMethod }

	outputs := map[string]string{
		"%v":           fmt.Sprintf("%v", v),
		"%+v":          fmt.Sprintf("%+v", v),
		"%#v":          fmt.Sprintf("%#v", v),
		"%s":           fmt.Sprintf("%s", v),
		"%q":           fmt.Sprintf("%q", v),
		"%x":           fmt.Sprintf("%x", v),
		"String":       v.String(),
		"GoString":     v.GoString(),
		"method %+v":   fmt.Sprintf("%+v", m),
		"method %#v":   fmt.Sprintf("%#v", m),
		"holder %+v":   fmt.Sprintf("%+v", holder{m}),
		"holder %#v":   fmt.Sprintf("%#v", holder{m}),
		"errorf %v":    fmt.Errorf("wrap: %v", m).Error(),
		"slice %v":     fmt.Sprint([]domain.LoginVerifier{v}),
		"pointer %+v":  fmt.Sprintf("%+v", &m),
		"map value %v": fmt.Sprint(map[string]domain.LoginMethod{"k": m}),
	}
	for name, out := range outputs {
		require.NotContains(t, out, probeMaterial, "путь печати %q выдал материал: %s", name, out)
		require.NotContains(t, out, "PROBE.login.verifier", "путь печати %q выдал часть материала: %s", name, out)
	}

	// Положительный контроль: печать ПРОИЗВОДИТСЯ и несёт соседние поля —
	// иначе «материала нет» было бы верно и о пустом выводе.
	require.Contains(t, outputs["method %+v"], "usr0000000000000lm01",
		"соседнее поле обязано печататься — иначе проба судит пустой вывод")
	require.Contains(t, outputs["%v"], "redacted", "материал обязан заменяться названной заглушкой")
}

func TestLoginVerifier_NeverLogged(t *testing.T) {
	v, err := domain.NewLoginVerifier(probeMaterial)
	require.NoError(t, err)
	m := domain.LoginMethod{UserID: "usr0000000000000lm02", Kind: domain.LoginMethodPassword, Verifier: v}

	for _, h := range []struct {
		name string
		mk   func(*bytes.Buffer) slog.Handler
	}{
		{"text", func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
		{"json", func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
	} {
		var buf bytes.Buffer
		log := slog.New(h.mk(&buf))
		// Идентификатор человека — отдельным атрибутом: JSON-обработчик на строке
		// способа получает отказ сериализации целиком (так и задумано), и соседнее
		// поле внутри неё не печатается вовсе.
		log.Info("login method", "user_id", m.UserID, "verifier", v, "method", m, slog.Any("any", v))
		out := buf.String()
		require.NotContains(t, out, probeMaterial, "журнал %s выдал материал: %s", h.name, out)
		require.Contains(t, out, "usr0000000000000lm02",
			"журнал %s обязан нести соседнее поле — иначе проба судит пустую строку", h.name)
	}
}

// TestLoginVerifier_RefusesSerialization — сериализация отказывает ГРОМКО, а не
// молча выдаёт пустое: молча выданное `{}` читалось бы как «материала нет», а
// значит было бы ложью о строке.
func TestLoginVerifier_RefusesSerialization(t *testing.T) {
	v, err := domain.NewLoginVerifier(probeMaterial)
	require.NoError(t, err)

	_, err = json.Marshal(v)
	require.Error(t, err, "JSON материала обязан отказывать")
	require.NotContains(t, err.Error(), probeMaterial, "отказ сериализации не вправе нести материал")

	_, err = json.Marshal(domain.LoginMethod{UserID: "usr0000000000000lm03", Kind: domain.LoginMethodPassword, Verifier: v})
	require.Error(t, err, "JSON строки способа обязан отказывать: материал внутри неё")

	_, err = v.MarshalText()
	require.Error(t, err, "текстовая форма материала обязана отказывать")

	// Положительный контроль: соседний тип этого же файла сериализуется —
	// значит отказ принадлежит материалу, а не всему, что проходит через json.
	raw, err := json.Marshal(domain.LoginMethodPassword)
	require.NoError(t, err)
	require.Equal(t, `"password"`, string(raw))
}

func TestLoginMethod_Validate(t *testing.T) {
	v, err := domain.NewLoginVerifier(probeMaterial)
	require.NoError(t, err)
	ok := domain.LoginMethod{UserID: "usr0000000000000lm04", Kind: domain.LoginMethodPassword, Verifier: v}
	require.NoError(t, ok.Validate(), "положительный контроль: полная строка проходит")

	cases := map[string]struct {
		m    domain.LoginMethod
		want string
	}{
		"человека нет":   {domain.LoginMethod{Kind: domain.LoginMethodPassword, Verifier: v}, "login_method.user_id: required"},
		"вида нет":       {domain.LoginMethod{UserID: ok.UserID, Verifier: v}, "login_method.kind"},
		"вид чужой":      {domain.LoginMethod{UserID: ok.UserID, Kind: "totp", Verifier: v}, "login_method.kind"},
		"материала нет":  {domain.LoginMethod{UserID: ok.UserID, Kind: domain.LoginMethodPassword}, "login_method.verifier: required"},
		"нулевой способ": {domain.LoginMethod{}, "login_method.user_id: required"},
	}
	for name, c := range cases {
		err := c.m.Validate()
		require.Error(t, err, "%s: строка обязана быть отвергнута", name)
		require.Contains(t, err.Error(), c.want, "%s: отказ обязан называть поле", name)
		require.False(t, strings.Contains(err.Error(), probeMaterial), "%s: отказ не вправе нести материал", name)
	}
}
