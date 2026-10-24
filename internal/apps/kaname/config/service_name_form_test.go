// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_name_form_test.go — ФОРМА ИМЕНИ СЛУЖБЫ в SPIFFE-идентификаторе
// объявляется посадкой тем же порядком, что домен доверия (kaname#308).
//
// Прежде форма стояла литералом в страже прав: учётная запись сертификата
// разбиралась только с приставкой имени другого продукта. Установка, называвшая
// свои учётки иначе, поднималась зелёной — взаимный TLS сходился, оба стража
// старта молчали, — а полоса входа отвечала голым отказом каждому запросу.
//
// Страж утверждается через настройку службы целиком (переменная → Load →
// Validate): так проба судит тот же путь подачи, которым величину задаёт
// оператор, а не поле структуры, которое оператору недоступно.
package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const (
	serviceNameFormKey = "authn.service-name-form"
	serviceNameFormEnv = "KANAME_AUTHN__SERVICE_NAME_FORM"
)

// loadValidated — настройка службы из окружения и вердикт стража старта.
//
// Профиль здесь неполон намеренно: страж отвечает множеством отказов, и проба
// спрашивает только о ТОМ, который называет форму имени службы. Отказ по чужой
// ручке на её вердикт не влияет — потому утверждение и стоит на имени ручки, а
// не на «ошибки нет».
func loadValidated(t *testing.T, form string, set bool) error {
	t.Helper()
	if set {
		t.Setenv(serviceNameFormEnv, form)
	}
	cfg, err := config.Load("")
	require.NoError(t, err)
	return cfg.Validate()
}

// refusesForm — среди отказов стража есть отказ о форме имени службы.
func refusesForm(err error) bool {
	return err != nil && strings.Contains(err.Error(), serviceNameFormKey)
}

// Отрицание: форма не объявлена — пуск отвергается на ЛЮБОМ старте, как у
// домена доверия. Без формы ни одна учётная запись сертификата не узнаётся
// модульной, и процесс отверг бы каждого соседа молча.
func TestServiceNameForm_UndeclaredRefusesToStartNamingTheKnob(t *testing.T) {
	err := loadValidated(t, "", false)
	require.True(t, refusesForm(err),
		"форма имени службы не объявлена, а страж старта о ней молчит: установка поднимется "+
			"и не узнает ни одного своего модуля; отказ обязан называть %s: %v", serviceNameFormKey, err)
	require.Contains(t, err.Error(), serviceNameFormEnv, "отказ обязан называть переменную: %v", err)
}

// Отрицание: форма написана без заполнителя имени службы — разобрать по ней не
// выйдет ни одного имени, и значение ничего не объявляет.
func TestServiceNameForm_WithoutThePlaceholderRefusesToStart(t *testing.T) {
	for name, v := range map[string]string{
		"одна приставка":        "acme-",
		"два заполнителя":       "{service}-{service}",
		"косая черта в форме":   "acme/{service}",
		"верхний регистр":       "Acme-{service}",
		"пробел внутри формы":   "acme {service}",
		"заполнитель с опиской": "acme-{svc}",
	} {
		t.Run(name, func(t *testing.T) {
			err := loadValidated(t, v, true)
			require.Truef(t, refusesForm(err),
				"форма %q принята: по ней не разбирается ни одно имя службы, а пуск идёт: %v", v, err)
		})
	}
}

// Инъекция F1 ревью сборки k1: форма без приставки — отказ старта тем же путём
// подачи, которым её задаёт оператор. Без приставки модульность учётки решает
// одно совпадение её имени с коротким именем службы, и пол «проверенный модуль»
// сужает не больше, чем имя учётки. Близнец — те же записи с приставкой в
// TestServiceNameForm_DeclaredFormIsAccepted.
func TestServiceNameForm_WithoutAPrefixRefusesToStart(t *testing.T) {
	for _, v := range []string{"{service}", "{service}-sa", "-{service}"} {
		t.Run(v, func(t *testing.T) {
			err := loadValidated(t, v, true)
			require.Truef(t, refusesForm(err),
				"форма %q без приставки принята стражем старта: модулем назовётся всякая учётка, "+
					"чьё имя совпало с именем службы: %v", v, err)
		})
	}
}

// Положительный близнец: объявленная законная форма отказа о себе не даёт —
// с приставкой, с приставкой и окончанием, с приставкой без разделителя.
func TestServiceNameForm_DeclaredFormIsAccepted(t *testing.T) {
	for _, v := range []string{"acme-{service}", "acme-{service}-sa", "team.a-{service}", "a{service}"} {
		t.Run(v, func(t *testing.T) {
			err := loadValidated(t, v, true)
			require.Falsef(t, refusesForm(err),
				"законная форма %q отвергнута стражем старта: %v", v, err)
		})
	}
}
