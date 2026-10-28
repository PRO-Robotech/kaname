// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_name_form_test.go — перечень читает учётки ОБЪЯВЛЕННОЙ формой имени
// службы (kaname#308), а не приставкой, вписанной в разбор.
//
// Каждое отрицание стоит в паре с законным близнецом, отличным от него ровно
// одним фактом — объявленной формой либо учёткой записи.
package moduleidentity

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// Инъекция предмета: установка объявила форму `acme-{service}`, а запись
// перечня названа учёткой другой приставки — перечень не собирается, и отказ
// называет запись и форму. Близнец — та же запись учёткой объявленной формы:
// собирается, и имя службы прочитано формой.
func TestParse_EntryOfAForeignFormIsRefusedNamingTheForm(t *testing.T) {
	form := servicesan.NewForm("acme-{service}")

	_, err := Parse(form, []string{"platform/other-api-gateway=edge"})
	require.Error(t, err, "запись чужой формы принята: перечень не спрашивает объявленную форму")
	require.ErrorContains(t, err, "platform/other-api-gateway")
	require.ErrorContains(t, err, "acme-{service}")

	r, err := Parse(form, []string{"platform/acme-api-gateway=edge"})
	require.NoError(t, err, "запись объявленной формы не принята — близнец отрицания")
	id, ok := r.Lookup(domain, "spiffe://kaname.test/ns/platform/sa/acme-api-gateway")
	require.True(t, ok)
	require.Equal(t, "api-gateway", id.Service)
}

// Тот же сертификат при другой объявленной форме модулем не признаётся: учётку
// `kacho-vpc` перечень формы `other-{service}` не объявляет и объявить не может.
// Близнец — форма, которой учётка сертификата названа на самом деле.
func TestLookup_CertificateOfAnotherFormIsNotAModule(t *testing.T) {
	const san = "spiffe://kaname.test/ns/kacho/sa/kacho-vpc"

	foreign, err := Parse(servicesan.NewForm("other-{service}"), []string{"kacho/other-vpc=module-writer"})
	require.NoError(t, err)
	_, ok := foreign.Lookup(domain, san)
	require.False(t, ok, "сертификат учётки не объявленной формы признан модулем")

	declared, err := Parse(servicesan.NewForm("kacho-{service}"), []string{"kacho/kacho-vpc=module-writer"})
	require.NoError(t, err)
	id, ok := declared.Lookup(domain, san)
	require.True(t, ok, "сертификат учётки объявленной формы не признан — близнец отрицания")
	require.Equal(t, "vpc", id.Service)
}

// Окончание формы снимается так же, как приставка: имя службы — между ними.
func TestParse_FormSuffixIsCutFromTheService(t *testing.T) {
	r, err := Parse(servicesan.NewForm("acme-{service}-sa"), []string{"platform/acme-vpc-sa=module-writer"})
	require.NoError(t, err)
	id, ok := r.Lookup(domain, "spiffe://kaname.test/ns/platform/sa/acme-vpc-sa")
	require.True(t, ok)
	require.Equal(t, "vpc", id.Service)

	_, err = Parse(servicesan.NewForm("acme-{service}-sa"), []string{"platform/acme-vpc=module-writer"})
	require.Error(t, err, "учётка без объявленного окончания принята записью")
}

// Необъявленная и незаконная форма не собирают перечня с записями: имя службы
// из учётки прочесть нечем. Пустой перечень при необъявленной форме — ноль без
// ошибки: о форме отказывает её страж, а признавать перечню некого.
func TestParse_UndeclaredOrInvalidFormReadsNoEntry(t *testing.T) {
	for name, form := range map[string]servicesan.Form{
		"не объявлена":             {},
		"без заполнителя":          servicesan.NewForm("acme-"),
		"без приставки":            servicesan.NewForm("{service}"),
		"край с разделителем":      servicesan.NewForm("-acme-{service}"),
		"два заполнителя":          servicesan.NewForm("acme-{service}-{service}"),
		"знак вне имени учётки":    servicesan.NewForm("Acme-{service}"),
		"запись из одних пробелов": servicesan.NewForm("   "),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(form, []string{"kacho/kacho-vpc=module-writer"})
			require.Error(t, err, "перечень собран мимо формы имени службы")
			require.ErrorContains(t, err, "service name form")

			r, err := Parse(form, nil)
			require.NoError(t, err)
			require.False(t, r.IsDeclared())
		})
	}
}

// Имя службы учётки перечень читает той же формой, которой собран; нулевой
// перечень не читает никого.
func TestRoster_ServiceFromAccountReadsTheDeclaredForm(t *testing.T) {
	r, err := Parse(servicesan.NewForm("acme-{service}"), []string{"platform/acme-vpc=module-writer"})
	require.NoError(t, err)

	svc, ok := r.ServiceFromAccount("acme-compute")
	require.True(t, ok)
	require.Equal(t, "compute", svc)

	_, ok = r.ServiceFromAccount("kacho-compute")
	require.False(t, ok, "учётка чужой формы прочитана службой")

	_, ok = Roster{}.ServiceFromAccount("acme-compute")
	require.False(t, ok, "нулевой перечень прочитал службу")
}

// Суд записи конфигурации на старте: объявлена ли пара, без суда о выпустившем
// центре. Привязанная к центру личность объявлена, хотя по одному имени
// (Lookup) не признаётся.
func TestRoster_DeclaresJudgesThePairOnly(t *testing.T) {
	r, err := ParseDeclared(servicesan.NewForm("kacho-{service}"),
		[]string{"kacho/kacho-api-gateway=edge@edge"}, []string{"edge"})
	require.NoError(t, err)

	const san = "spiffe://kaname.test/ns/kacho/sa/kacho-api-gateway"
	require.True(t, r.Declares(domain, san), "объявленная пара не объявлена")
	_, ok := r.Lookup(domain, san)
	require.False(t, ok, "привязанная к центру личность признана по одному имени")

	require.False(t, r.Declares(domain, "spiffe://kaname.test/ns/intruder/sa/kacho-api-gateway"),
		"пара необъявленного пространства объявлена")
	require.False(t, Roster{}.Declares(domain, san), "нулевой перечень объявил пару")
}
