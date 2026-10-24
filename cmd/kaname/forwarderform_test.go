// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// forwarderform_test.go — страж круга отправителей по форме имени службы
// (kaname#308): способность упасть и способность смолчать.
//
// Каждая инъекция меняет против контроля РОВНО ОДИН факт: запись круга, имя
// фронта либо объявление. Контроль — круг, который транспорт узнаёт целиком.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

const (
	formProbeDomain = "trust.example.test"
	formProbeForm   = "acme-{service}"
	// formProbeEdge — край в объявленной форме.
	formProbeEdge = "spiffe://" + formProbeDomain + "/ns/platform/sa/acme-api-gateway"
	// formProbeFront — собственный REST-фронт службы: учётка формы модулей не
	// несёт, узнаётся равенством имени.
	formProbeFront = "spiffe://" + formProbeDomain + "/ns/platform/sa/access"
)

func formProbeAuthN(form string, forwarders ...string) config.AuthNConfig {
	return config.AuthNConfig{
		TrustDomainName:      formProbeDomain,
		ServiceNameFormRaw:   form,
		TrustedForwarderSANs: forwarders,
	}
}

// Контроль: край формы и собственный фронт, чьё имя корень вывел из
// сертификата, — оба узнаются, отказа нет.
func TestForwardersRecognised_ControlCircleIsSilent(t *testing.T) {
	require.NoError(t, requireForwardersRecognised(
		formProbeAuthN(formProbeForm, formProbeEdge, formProbeFront), formProbeFront))
}

// Инъекция предмета задачи: учётка края названа ЧУЖОЙ формой. Взаимный TLS
// сходится, оба стража старта зелены — а пол отверг бы каждый вызов края.
func TestForwardersRecognised_AccountOfAForeignFormRefusesToStart(t *testing.T) {
	foreign := "spiffe://" + formProbeDomain + "/ns/platform/sa/other-api-gateway"
	err := requireForwardersRecognised(formProbeAuthN(formProbeForm, foreign, formProbeFront), formProbeFront)
	require.Error(t, err, "запись чужой формы принята: её предъявитель получал бы отказ на каждом вызове")
	for _, want := range []string{foreign, formProbeForm, formProbeDomain,
		"authn.trusted-forwarder-sans", "KANAME_AUTHN__TRUSTED_FORWARDER_SANS",
		"authn.service-name-form", "KANAME_AUTHN__SERVICE_NAME_FORM"} {
		require.Containsf(t, err.Error(), want, "отказ обязан называть %q: %v", want, err)
	}
	require.NotContains(t, err.Error(), formProbeEdge+`"`, "отказ назвал запись, которую транспорт узнаёт")
}

// Инъекция: та же учётка фронта, но фронта с удостоверением на посадке нет —
// имя ему не принадлежит никому, и запись не узнаётся.
func TestForwardersRecognised_FrontEntryWithoutAFrontRefuses(t *testing.T) {
	err := requireForwardersRecognised(formProbeAuthN(formProbeForm, formProbeEdge, formProbeFront), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), formProbeFront)
}

// Инъекция: запись чужого домена при законной форме учётки.
func TestForwardersRecognised_ForeignDomainRefuses(t *testing.T) {
	foreign := "spiffe://other.example.test/ns/platform/sa/acme-api-gateway"
	err := requireForwardersRecognised(formProbeAuthN(formProbeForm, foreign), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), foreign)
}

// Близнец инъекции: та же чужая на вид учётка становится законной, когда
// установка объявляет ЕЁ форму, — страж судит расхождение записи с
// объявлением, а не саму приставку.
func TestForwardersRecognised_DeclaringTheRealFormIsSilent(t *testing.T) {
	foreign := "spiffe://" + formProbeDomain + "/ns/platform/sa/other-api-gateway"
	require.NoError(t, requireForwardersRecognised(formProbeAuthN("other-{service}", foreign), ""))
}

// Молчание без предмета: пустой круг, необъявленные домен и форма судят свои
// стражи настройки, второе сообщение о том же разошлось бы с первым.
func TestForwardersRecognised_OtherGuardsSubjectsAreNotRestated(t *testing.T) {
	require.NoError(t, requireForwardersRecognised(formProbeAuthN(formProbeForm), ""), "пустой круг")
	require.NoError(t, requireForwardersRecognised(formProbeAuthN("", formProbeEdge), ""), "форма не объявлена")
	require.NoError(t, requireForwardersRecognised(formProbeAuthN("acme-", formProbeEdge), ""), "форма незаконна")
	undeclaredDomain := formProbeAuthN(formProbeForm, formProbeEdge)
	undeclaredDomain.TrustDomainName = ""
	require.NoError(t, requireForwardersRecognised(undeclaredDomain, ""), "домен не объявлен")
}

// probeServiceNameForm — форма имени службы, которой названы учётки проб этого
// пакета (`fwdGatewaySAN`, `acrTestGatewaySAN` и соседи): объявление установки,
// под которым пробы собирают политики вызывающего.
var probeServiceNameForm = servicesan.NewForm(probeServiceNameFormRaw)

// probeServiceNameFormRaw — та же форма записью, как её задаёт профиль.
const probeServiceNameFormRaw = "kacho-{service}"
