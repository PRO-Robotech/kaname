// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/buildflavor"
)

// releaseBuildRefusal — общая часть отказа стража сборки: по ней оператор
// узнаёт причину, а проба — что отказ произвёл именно этот страж.
const releaseBuildRefusal = "refused by a release build"

// validateBuildFlavor — СТРАЖ СБОРКИ (kaname#985): выпускной бинарь не
// исполняет ни режима разработки, ни опт-ина «круг отправителей не сужаем».
//
// Оба ослабляют проверку вызывающих, опирающуюся на клиентский сертификат:
// режим разработки снимает пол и рукава политики вызывающего внутреннего
// слушателя, опт-ин круга принимает переданную личность от любого пира. Пока их
// разрешало значение настройки, продовая посадка переходила в них одной
// строкой — и страж старта это принимал. Теперь их разрешает только признак
// тестовой сборки ([buildflavor.IsTestBuild]); значения настройки, снимающего
// этот отказ, нет.
//
// testBuild — аргумент, а не вызов внутри: так страж судим пробой на обоих
// исходах, хотя бинарь проб сам всегда тестовый.
func (c Config) validateBuildFlavor(testBuild bool) error {
	if testBuild {
		return nil
	}
	var errs error
	if c.AuthN.Mode == ModeDev {
		errs = multierr.Append(errs, fmt.Errorf("authn.mode=dev (env KANAME_AUTHN__MODE) is %s: the "+
			"development mode relaxes the caller checks of the internal listener, including the ones "+
			"resting on the client certificate, and only a test build (go build -tags %s) may run it; "+
			"set authn.mode to production or production-strict", releaseBuildRefusal, buildflavor.Tag))
	}
	if c.AuthN.TrustAnyForwarder {
		errs = multierr.Append(errs, fmt.Errorf("authn.trust-any-forwarder (env KANAME_AUTHN__TRUST_ANY_FORWARDER) "+
			"is %s: it lets any certificate-verified peer forward an end-user identity, and only a test "+
			"build (go build -tags %s) may run it; unset it and pin the forwarders in "+
			"authn.trusted-forwarder-sans", releaseBuildRefusal, buildflavor.Tag))
	}
	return errs
}
