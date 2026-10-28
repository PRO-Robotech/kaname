// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// forwarderform.go — каждая запись круга отправителей разбирается ТЕМ ЖЕ
// предикатом, которым её предъявителя разберёт транспорт (kaname#308).
//
// # Предмет
//
// Страж круга (`grpcsrv.TrustedForwarders.Require`) судит НЕПУСТОТУ перечня и
// формы записи не касается. Запись, которую пол политики вызывающего не узнает,
// бесполезна и вредна молча: её предъявитель проходит взаимный TLS, говорит за
// пользователя — и получает отказ на каждом вызове до маршрута, потому что пол
// не признаёт его модулем. Оба стража старта при этом зелены, и установка
// выглядит настроенной. Так выглядел дефект: учётка края называлась не той
// приставкой, которую разбор держал литералом, и ни один человек не входил.
//
// # Что значит «узнаёт транспорт»
//
// Пол признаёт предъявителя в двух случаях, и страж спрашивает ровно их:
// идентификатор разбирается объявленной формой имени службы в объявленном
// домене (`servicesan.Form.Parse` — тот же вызов, что у пола) либо РАВЕН имени
// собственного REST-фронта службы (то, что корень выводит из сертификата,
// который фронт фактически предъявляет, — `ownFrontHopSAN`).
//
// # Почему страж живёт в корне, а не в страже настройки
//
// Имя фронта приходит из сертификата, а сертификат читает корень: страж
// настройки его не видит. Без второго случая страж отверг бы законный круг
// стенда, где служба пересылает личность своим же листом.
package main

import (
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// requireForwardersRecognised — отказ старта, когда запись круга отправителей
// транспорт не узнает модулем.
//
// Пустой круг здесь не судится — его судит страж круга. Необъявленные домен и
// форма тоже: о них отказывают свои стражи (`Config.Validate`), и второе
// сообщение о том же предмете разошлось бы с первым. Отказ называет КАЖДУЮ
// неузнанную запись, форму, домен и обе ручки: оператор чинит либо запись, либо
// объявление формы, и обязан видеть обе стороны сразу.
func requireForwardersRecognised(authn config.AuthNConfig, ownFrontSAN string) error {
	domain, form := authn.TrustDomain(), authn.ServiceNameForm()
	if !domain.IsDeclared() || !form.Valid() {
		return nil
	}
	var unrecognised []string
	for _, san := range authn.TrustedForwarders().SANs() {
		if _, ok := form.Parse(domain, san); ok {
			continue
		}
		if ownFrontSAN != "" && san == ownFrontSAN {
			continue
		}
		unrecognised = append(unrecognised, san)
	}
	if len(unrecognised) == 0 {
		return nil
	}
	return fmt.Errorf("authn.trusted-forwarder-sans (env KANAME_AUTHN__TRUSTED_FORWARDER_SANS) declares %q, "+
		"and the transport does not recognize it as a module: its account is not of the declared form %q "+
		"(%s) in the trust domain %q, and it is not the service's own REST front either. Such a sender "+
		"passes mutual TLS and is refused on every call before routing — the sign-in lane included — "+
		"while both start guards stay green; name the account in the declared form, or declare the form "+
		"the installation really names its service accounts by; refusing to start",
		unrecognised, form.String(), config.ServiceNameFormKnob, domain.Name())
}
