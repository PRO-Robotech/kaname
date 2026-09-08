// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// authz_window_test.go — окно отзыва СОБСТВЕННОЙ ДВЕРИ не имеет умолчания
// (задача продукта #2307).
//
// # Предмет
//
// Кешируется только ПОЛОЖИТЕЛЬНЫЙ вердикт, поэтому срок жизни записи и ЕСТЬ
// время, в течение которого субъект с уже отобранным правом продолжает
// проходить. Это параметр безопасности, а не производительности.
//
// Соседи по платформе такое состояние отвергают стартом: дескриптор носителя
// (`pkg/servicecontract`) объявляет у окна отзыва, что умолчания у такой
// величины быть не может, и отказывает в пуске при неположительной. Собственная
// дверь службы строит кеш сама, минуя дескриптор, и стража не имела.
//
// # Почему это не «величина и так задана умолчанием процесса»
//
// Умолчание процесса (5s) закрывает НЕЗАДАННУЮ ручку и здесь не оспаривается.
// Оспаривается ЗАДАННЫЙ ноль: он объявлялся законным — «беру умолчание
// политики» — и уводил величину туда, где оператор её не выбирает. Для
// вынесенного модуля это умолчание живёт в ЧУЖОЙ ревизии: службa резолвит
// фундамент пином (`services/iam/go.mod`, `replace` — ноль), поэтому величина
// менялась бы не правкой политики, а бампом пина. Параметр безопасности,
// который нельзя изменить там, где он объявлен, — ничей.
//
// Отрицательная величина не объявлялась законной никогда и отвергается по тому
// же доводу: кеш построился бы на умолчании, а конфигурация утверждала бы иное.

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// authzWindowKnob — имя настройки, которое отказ обязан назвать. Оператор чинит
// посадку по имени ручки, а не по описанию беды.
const authzWindowKnob = "authz.cache-ttl"

// TestValidate_AuthZWindow_ZeroRefusesStart — несущее утверждение.
//
// Ноль здесь НЕ «кеша нет» и не «возьми умолчание»: это незаявленное окно
// отзыва, и выбирать его за оператора служба не вправе.
func TestValidate_AuthZWindow_ZeroRefusesStart(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeDev, config.ModeProduction} {
		t.Run(mode.String(), func(t *testing.T) {
			cfg := validAuthZWindowConfig(mode)
			cfg.AuthZ.CacheTTL = 0

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil при незаявленном окне отзыва собственной двери — "+
					"служба поднялась бы, выбрав окно отзыва за оператора (режим %s)", mode)
			}
			if !strings.Contains(err.Error(), authzWindowKnob) {
				t.Fatalf("отказ не называет настройку %q: %q", authzWindowKnob, err.Error())
			}
		})
	}
}

// TestValidate_AuthZWindow_NegativeRefusesStart — вторая неположительная
// величина. Отдельным утверждением, а не строкой предыдущего: ноль и
// отрицательное приходят разными путями (ноль — умолчанием карты настроек,
// отрицательное — опечаткой оператора), и проба, знающая только ноль, была бы
// слепа ко второму.
func TestValidate_AuthZWindow_NegativeRefusesStart(t *testing.T) {
	cfg := validAuthZWindowConfig(config.ModeProduction)
	cfg.AuthZ.CacheTTL = -time.Second

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil при отрицательном окне отзыва — кеш построился бы " +
			"на умолчании, а конфигурация утверждала бы иное")
	}
	if !strings.Contains(err.Error(), authzWindowKnob) {
		t.Fatalf("отказ не называет настройку %q: %q", authzWindowKnob, err.Error())
	}
}

// TestValidate_AuthZWindow_DeclaredIsAccepted — ЗАКОННЫЙ БЛИЗНЕЦ, и он несущий:
// без него оба отрицания выше зеленели бы на страже, отвергающем ЛЮБУЮ величину.
func TestValidate_AuthZWindow_DeclaredIsAccepted(t *testing.T) {
	cfg := validAuthZWindowConfig(config.ModeProduction)
	cfg.AuthZ.CacheTTL = 5 * time.Second

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v при объявленном окне отзыва — годная посадка отвергнута", err)
	}
}

// TestValidate_AuthZWindow_RefusalNamesTheRuleNotTheValue — текст отказа читает
// ОПЕРАТОР: он обязан узнать, какую ручку задать и почему у неё нет умолчания.
//
// Довод берётся тот же, что у соседей по платформе, и это не оформление: две
// формулировки об одном предмете разошлись бы, и оператор, прочитавший обе,
// решал бы, какая из них действует.
func TestValidate_AuthZWindow_RefusalNamesTheRuleNotTheValue(t *testing.T) {
	cfg := validAuthZWindowConfig(config.ModeProduction)
	cfg.AuthZ.CacheTTL = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil — предмет утверждения отсутствует")
	}
	// Регистр не судится: довод стоит в начале предложения и пишется с
	// прописной. Предмет утверждения — СОДЕРЖАНИЕ отказа, а не его вёрстка, и
	// проба, различающая регистр, краснела бы на правке пунктуации.
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "окно отзыва") {
		t.Fatalf("отказ не называет ПРЕДМЕТ величины («окно отзыва»): %q", err.Error())
	}
	if !strings.Contains(msg, "умолчания") {
		t.Fatalf("отказ не называет ПРАВИЛО (умолчания у величины нет): %q", err.Error())
	}
}

// validAuthZWindowConfig — годная посадка, у которой переменная ровно одна:
// окно отзыва собственной двери. Прочие оси посеяны так же, как в goodEndpoints,
// иначе отказ приходил бы не по предмету пробы.
func validAuthZWindowConfig(mode config.Mode) config.Config {
	cfg := goodEndpoints(mode, "require")
	cfg.AuthN.HookSharedSecret = "a-strong-shared-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	return cfg
}
