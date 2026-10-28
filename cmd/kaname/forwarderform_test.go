// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// forwarderform_test.go — страж круга отправителей по перечню личностей модулей
// и форме имени службы (kaname#308, kaname#984): способность упасть и
// способность смолчать.
//
// Каждая инъекция меняет против контроля РОВНО ОДИН факт: запись круга, имя
// фронта, перечень либо объявление формы. Контроль — круг, который транспорт
// узнаёт целиком.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

const (
	formProbeDomain = "trust.example.test"
	formProbeForm   = "acme-{service}"
	// formProbeEdge — край в объявленной форме.
	formProbeEdge = "spiffe://" + formProbeDomain + "/ns/platform/sa/acme-api-gateway"
	// formProbeFront — собственный REST-фронт службы: в перечне личностей не
	// стоит, узнаётся равенством имени.
	formProbeFront = "spiffe://" + formProbeDomain + "/ns/platform/sa/access"
)

func formProbeAuthN(form string, forwarders ...string) config.AuthNConfig {
	return config.AuthNConfig{
		TrustDomainName:      formProbeDomain,
		ServiceNameFormRaw:   form,
		TrustedForwarderSANs: forwarders,
	}
}

// formProbeRoster — перечень личностей под формой form; записей нет — нулевой
// перечень (необъявленная форма записей не собирает).
func formProbeRoster(t *testing.T, form string, entries ...string) moduleidentity.Roster {
	t.Helper()
	r, err := moduleidentity.Parse(servicesan.NewForm(form), entries)
	require.NoError(t, err)
	return r
}

// formProbeEdgeEntry — запись перечня, объявляющая край formProbeEdge.
const formProbeEdgeEntry = "platform/acme-api-gateway=edge"

// Контроль: объявленный край и собственный фронт, чьё имя корень вывел из
// сертификата, — оба узнаются, отказа нет.
func TestForwardersRecognised_ControlCircleIsSilent(t *testing.T) {
	require.NoError(t, requireForwardersRecognised(
		formProbeAuthN(formProbeForm, formProbeEdge, formProbeFront),
		formProbeRoster(t, formProbeForm, formProbeEdgeEntry), formProbeFront))
}

// Инъекция предмета задачи: учётка края названа ЧУЖОЙ формой — объявить её
// перечнем под объявленной формой нельзя, и пары в перечне нет. Взаимный TLS
// сходится, оба стража старта зелены — а пол отверг бы каждый вызов края.
func TestForwardersRecognised_AccountOfAForeignFormRefusesToStart(t *testing.T) {
	foreign := "spiffe://" + formProbeDomain + "/ns/platform/sa/other-api-gateway"
	err := requireForwardersRecognised(formProbeAuthN(formProbeForm, foreign, formProbeFront),
		formProbeRoster(t, formProbeForm, formProbeEdgeEntry), formProbeFront)
	require.Error(t, err, "запись чужой формы принята: её предъявитель получал бы отказ на каждом вызове")
	for _, want := range []string{foreign, formProbeForm, formProbeDomain,
		"authn.trusted-forwarder-sans", "KANAME_AUTHN__TRUSTED_FORWARDER_SANS",
		"authn.module-identities", "KANAME_AUTHN__MODULE_IDENTITIES",
		"authn.service-name-form", "KANAME_AUTHN__SERVICE_NAME_FORM"} {
		require.Containsf(t, err.Error(), want, "отказ обязан называть %q: %v", want, err)
	}
	require.NotContains(t, err.Error(), formProbeEdge+`"`, "отказ назвал запись, которую транспорт узнаёт")
}

// Инъекция (kaname#984): учётка края законной формы, но её пара в перечне не
// объявлена — пространство другое. Пол модулем её не признаёт.
func TestForwardersRecognised_UndeclaredPairRefuses(t *testing.T) {
	err := requireForwardersRecognised(formProbeAuthN(formProbeForm, formProbeEdge),
		formProbeRoster(t, formProbeForm, "edge-ns/acme-api-gateway=edge"), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), formProbeEdge)
}

// Инъекция: та же учётка фронта, но фронта с удостоверением на посадке нет —
// имя ему не принадлежит никому, и запись не узнаётся.
func TestForwardersRecognised_FrontEntryWithoutAFrontRefuses(t *testing.T) {
	err := requireForwardersRecognised(formProbeAuthN(formProbeForm, formProbeEdge, formProbeFront),
		formProbeRoster(t, formProbeForm, formProbeEdgeEntry), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), formProbeFront)
}

// Инъекция: запись чужого домена при законной форме учётки и объявленной паре.
func TestForwardersRecognised_ForeignDomainRefuses(t *testing.T) {
	foreign := "spiffe://other.example.test/ns/platform/sa/acme-api-gateway"
	err := requireForwardersRecognised(formProbeAuthN(formProbeForm, foreign),
		formProbeRoster(t, formProbeForm, formProbeEdgeEntry), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), foreign)
}

// Близнец инъекции: та же чужая на вид учётка становится законной, когда
// установка объявляет ЕЁ форму и её пару, — страж судит расхождение записи с
// объявлением, а не саму приставку.
func TestForwardersRecognised_DeclaringTheRealFormIsSilent(t *testing.T) {
	foreign := "spiffe://" + formProbeDomain + "/ns/platform/sa/other-api-gateway"
	require.NoError(t, requireForwardersRecognised(formProbeAuthN("other-{service}", foreign),
		formProbeRoster(t, "other-{service}", "platform/other-api-gateway=edge"), ""))
}

// Молчание без предмета: пустой круг, необъявленные домен и форма судят свои
// стражи настройки, второе сообщение о том же разошлось бы с первым.
func TestForwardersRecognised_OtherGuardsSubjectsAreNotRestated(t *testing.T) {
	declared := formProbeRoster(t, formProbeForm, formProbeEdgeEntry)
	require.NoError(t, requireForwardersRecognised(formProbeAuthN(formProbeForm), declared, ""), "пустой круг")
	require.NoError(t, requireForwardersRecognised(formProbeAuthN("", formProbeEdge),
		moduleidentity.Roster{}, ""), "форма не объявлена")
	require.NoError(t, requireForwardersRecognised(formProbeAuthN("acme-", formProbeEdge),
		moduleidentity.Roster{}, ""), "форма незаконна")
	undeclaredDomain := formProbeAuthN(formProbeForm, formProbeEdge)
	undeclaredDomain.TrustDomainName = ""
	require.NoError(t, requireForwardersRecognised(undeclaredDomain, declared, ""), "домен не объявлен")
}

// probeServiceNameForm — форма имени службы, которой названы учётки проб этого
// пакета (`fwdGatewaySAN`, `acrTestGatewaySAN` и соседи): объявление установки,
// под которым пробы собирают перечень личностей (testModuleRoster).
var probeServiceNameForm = servicesan.NewForm(probeServiceNameFormRaw)

// probeServiceNameFormRaw — та же форма записью, как её задаёт профиль.
const probeServiceNameFormRaw = "kacho-{service}"
