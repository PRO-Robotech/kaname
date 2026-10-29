// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// servicesan_test.go — чтение имени службы из учётки по объявленной форме.
//
// Каждое отрицание стоит в паре с положительным близнецом, отличным от него
// ровно одним фактом: чтение, отвергающее всё, проходило бы по всякому
// отрицанию и не проверяло бы ничего. Разбор самого SPIFFE-идентификатора —
// у перечня личностей модулей (`moduleidentity.ParseSAN`) и судится его пробами.
package servicesan_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// Инъекция предмета задачи: учётка чужой формы. Установка объявила `acme-`, а
// предъявлено имя с другой приставкой — службы в нём форма не читает. Близнец —
// та же учётка с объявленной приставкой.
func TestService_AccountOfAForeignFormIsNotAModule(t *testing.T) {
	form := servicesan.NewForm("acme-{service}")

	_, ok := form.Service("other-api-gateway")
	require.False(t, ok, "учётка чужой формы прочитана службой: чтение не спрашивает объявленную форму")

	svc, ok := form.Service("acme-api-gateway")
	require.True(t, ok, "учётка объявленной формы не прочитана — близнец отрицания")
	require.Equal(t, "api-gateway", svc)
}

// Инъекция F1 ревью сборки k1: форма без приставки модуль не сужает ничем,
// кроме совпадения имени учётки с коротким именем службы, — и потому не форма.
// По ней не читается никто, в том числе учётка, равная имени службы, и учётка
// с окончанием формы. Близнец — та же учётка под формой с приставкой: отличие
// ровно одно, приставка.
func TestService_FormWithoutAPrefixRecognizesNobody(t *testing.T) {
	for raw, account := range map[string]string{
		"{service}":    "api-gateway",
		"{service}-sa": "api-gateway-sa",
	} {
		_, ok := servicesan.NewForm(raw).Service(account)
		require.Falsef(t, ok, "форма %q без приставки прочитала службой учётку %q: модульность решает "+
			"одно совпадение имени учётки с именем службы", raw, account)

		svc, ok := servicesan.NewForm("acme-" + raw).Service("acme-" + account)
		require.Truef(t, ok, "та же учётка под формой с приставкой не прочитана — близнец отрицания")
		require.Equal(t, "api-gateway", svc)
	}
}

// Окончание формы снимается так же, как приставка.
func TestService_SuffixIsCut(t *testing.T) {
	form := servicesan.NewForm("acme-{service}-sa")
	svc, ok := form.Service("acme-vpc-sa")
	require.True(t, ok)
	require.Equal(t, "vpc", svc)

	_, ok = form.Service("acme-vpc")
	require.False(t, ok, "учётка без объявленного окончания прочитана службой")
}

// Необъявленная форма не читает никого.
func TestService_ZeroFormRecognizesNobody(t *testing.T) {
	var zeroForm servicesan.Form
	_, ok := zeroForm.Service("vpc")
	require.False(t, ok, "необъявленная форма прочитала службу")
}

// Незаконная запись формы не читает ничего — даже учётку, похожую на неё.
func TestService_InvalidFormRecognizesNobody(t *testing.T) {
	form := servicesan.NewForm("acme-")
	_, ok := form.Service("acme-vpc")
	require.False(t, ok)
}

// Учётки, в которых законная форма службы не читает.
func TestService_MalformedAccountsAreRefused(t *testing.T) {
	form := servicesan.NewForm("acme-{service}")
	for name, account := range map[string]string{
		"пустое имя службы":       "acme-",
		"хвост после учётки":      "acme-vpc/extra",
		"приставка внутри учётки": "x-acme-vpc",
		"пустая учётка":           "",
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := form.Service(account)
			require.Falsef(t, ok, "%q прочитана службой", account)
		})
	}
}

// Учётка, которую форма называет службой, разбирается обратно в ту же службу —
// одна форма, а не две.
func TestAccountAndServiceAreInverse(t *testing.T) {
	for _, raw := range []string{"acme-{service}", "acme-{service}-sa", "a{service}", "a.b-{service}-c"} {
		form := servicesan.NewForm(raw)
		account := form.Account("api-gateway")
		svc, ok := form.Service(account)
		require.Truef(t, ok, "форма %q не читает собственную учётку %q", raw, account)
		require.Equal(t, "api-gateway", svc)
	}
	require.Empty(t, servicesan.NewForm("acme-").Account("vpc"), "незаконная форма собрала учётку")
	require.Empty(t, servicesan.NewForm("{service}").Account("vpc"), "форма без приставки собрала учётку")
	require.Empty(t, servicesan.NewForm("acme-{service}").Account(""), "собрана учётка без имени службы")
}

// Страж формы: отказ называет ручку, заполнитель и образец; законная форма
// отказа не даёт.
func TestRequire(t *testing.T) {
	gate := servicesan.Gate{Knob: "probe.knob (env PROBE_KNOB)"}

	err := servicesan.NewForm("").Require(gate)
	require.Error(t, err, "необъявленная форма прошла стража")
	for _, want := range []string{gate.Knob, servicesan.Placeholder, servicesan.Sample} {
		require.Contains(t, err.Error(), want)
	}

	for _, bad := range []string{"acme-", "{service}{service}", "Acme-{service}", "acme {service}", "a/{service}"} {
		err := servicesan.NewForm(bad).Require(gate)
		require.Errorf(t, err, "незаконная форма %q прошла стража", bad)
		require.Contains(t, err.Error(), gate.Knob)
		require.Contains(t, err.Error(), bad)
	}

	for _, good := range []string{"acme-{service}", "  acme-{service}  ", "acme-{service}-sa", "a{service}",
		"0.{service}", servicesan.Sample} {
		require.NoErrorf(t, servicesan.NewForm(good).Require(gate), "законная форма %q отвергнута", good)
	}
}

// Инъекция F1 ревью сборки k1 у стража: форма без приставки — отказ старта, и
// отказ называет причину (приставку), а не только ручку. Близнецы — те же формы
// с приставкой в TestRequire: отличие ровно одно.
func TestRequire_FormWithoutAPrefixRefusesNamingThePrefix(t *testing.T) {
	gate := servicesan.Gate{Knob: "probe.knob (env PROBE_KNOB)"}
	for _, bad := range []string{"{service}", "  {service}  ", "{service}-sa"} {
		form := servicesan.NewForm(bad)
		require.Falsef(t, form.Valid(), "форма %q без приставки названа законной", bad)
		err := form.Require(gate)
		require.Errorf(t, err, "форма %q без приставки прошла стража старта", bad)
		for _, want := range []string{gate.Knob, strings.TrimSpace(bad), "prefix", servicesan.Sample} {
			require.Containsf(t, err.Error(), want, "отказ о форме %q обязан называть %q: %v", bad, want, err)
		}
	}
}

// Приставка и окончание стоят на краях имени учётки кластера, а имя учётки
// начинается и кончается буквой или цифрой. Приставка из одного разделителя
// либо окончание, им кончающееся, не называют ни одной возможной учётки: по
// такой форме не узнаётся никто, а установка выглядела бы настроенной.
func TestRequire_FormWhoseAccountsCannotExistRefuses(t *testing.T) {
	gate := servicesan.Gate{Knob: "probe.knob (env PROBE_KNOB)"}
	for _, bad := range []string{"-{service}", ".acme-{service}", "acme-{service}-", "acme-{service}."} {
		err := servicesan.NewForm(bad).Require(gate)
		require.Errorf(t, err, "форма %q, по которой не складывается ни одна учётка, прошла стража", bad)
		require.Contains(t, err.Error(), bad)
	}
}

// Пробелы по краям записи — не часть формы; запись печатается без них.
func TestNewForm_TrimsTheWrittenValue(t *testing.T) {
	form := servicesan.NewForm("  acme-{service}\t")
	require.True(t, form.Valid())
	require.Equal(t, "acme-{service}", form.String())
	require.True(t, strings.HasPrefix(servicesan.Form{}.String(), "<"), "ноль печатается словом, а не пустой строкой")
}
