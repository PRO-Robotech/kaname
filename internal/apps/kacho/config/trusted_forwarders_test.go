// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// trusted_forwarders_test.go — ручка и стража старта для измерения «кому
// разрешено ПЕРЕДАВАТЬ личность конечного пользователя».
//
// Предмет. Оба листенера iam монтируют доверенную пару CertIdentityExtract →
// TrustedPrincipalExtract, но БЕЗ списка отправителей. По контракту corelib
// (pkg/grpcsrv principalIsTrusted) пустой список означает не «никому», а «любому
// пиру, предъявившему сертификат внутреннего центра»: сосед присылает заголовки
// x-kacho-principal-* с именем жертвы, и решение о правах принимается от её имени.
//
// Здесь проверяются ДВЕ вещи конфигурационного слоя: (1) аксессор считает так же,
// как corelib (пустые записи отбрасываются), и (2) боевой режим не стартует, пока
// круг не сужен. Поведение самой цепочки — в cmd/kacho-iam.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// forwarderKnobName — имя настройки, которое обязано прозвучать в отказе старта:
// оператору нужно знать, что именно заполнять.
const forwarderKnobName = "authn.trusted-forwarder-sans"

const (
	gatewaySAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	vpcSAN     = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
)

// forwarderCfg — конфигурация, у которой ВСЕ прочие боевые инварианты уже
// выполнены (секреты, sslmode), чтобы единственной переменной остался список
// отправителей.
func forwarderCfg(mode config.Mode, sans ...string) config.Config {
	cfg := goodEndpoints(mode, "require")
	cfg.AuthN.HookSharedSecret = "a-strong-shared-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.AuthN.TrustedForwarderSANs = sans
	return cfg
}

// TestTrustedForwarders_DropsBlankEntries — аксессор обязан считать ровно так же,
// как corelib: WithTrustedForwarders пропускает только непустые строки, поэтому
// список из одних пустых записей вырождается там в пустое множество, то есть
// снова в «доверяем любому». Если аксессор считает такую строку заполненной,
// стража пропустит дыру.
func TestTrustedForwarders_DropsBlankEntries(t *testing.T) {
	cfg := forwarderCfg(config.ModeProduction, "", "  ", "\t")
	if got := cfg.AuthN.TrustedForwarders(); got.IsNarrowed() {
		t.Fatalf("blank-only list resolved to %v — corelib drops empty strings, so the circle stays open", got)
	}
}

// TestTrustedForwarders_TrimsSurroundingSpace — оператор, написавший список через
// «запятая-пробел», не должен получить молчаливый отказ в обслуживании законному
// отправителю: corelib сравнивает личность сертификата побайтово, и запись
// " spiffe://…" не совпала бы ни с одним пиром. Круг от среза не расширяется — в
// него попадают ровно перечисленные строки.
func TestTrustedForwarders_TrimsSurroundingSpace(t *testing.T) {
	cfg := forwarderCfg(config.ModeProduction, " "+gatewaySAN+" ")
	got := cfg.AuthN.TrustedForwarders().SANs()
	if len(got) != 1 || got[0] != gatewaySAN {
		t.Fatalf("TrustedForwarders() = %#v, want exactly [%q]", got, gatewaySAN)
	}
}

// TestValidate_ProductionRefusesEmptyForwarderAllowList — сердце правки: боевой
// режим не стартует, пока круг отправителей не сужен.
//
// RED до правки: Validate() не знает про это измерение — процесс поднимается и
// принимает переданную личность от любого пира с сертификатом.
func TestValidate_ProductionRefusesEmptyForwarderAllowList(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeProduction, config.ModeProductionStrict} {
		t.Run(mode.String(), func(t *testing.T) {
			err := forwarderCfg(mode).Validate()
			if err == nil {
				t.Fatalf("%s mode started with an EMPTY trusted-forwarder allow-list: corelib narrows "+
					"the circle only when the list is non-empty, so any certificate-verified neighbour "+
					"may forward someone else's identity and have the authorization decision made in "+
					"that victim's name", mode)
			}
			if !strings.Contains(err.Error(), forwarderKnobName) {
				t.Fatalf("the refusal must name the setting the operator has to fill, got: %v", err)
			}
		})
	}
}

// TestValidate_ProductionRefusesBlankOnlyForwarderAllowList — `SANS=","` не должен
// проходить гейт: для corelib такой список пуст.
func TestValidate_ProductionRefusesBlankOnlyForwarderAllowList(t *testing.T) {
	err := forwarderCfg(config.ModeProduction, "", " ").Validate()
	if err == nil || !strings.Contains(err.Error(), forwarderKnobName) {
		t.Fatalf("a list of blank entries passed the guard (err=%v): corelib drops empty strings, "+
			"so the resulting allow-list is empty and trusts any verified peer", err)
	}
}

// TestValidate_ProductionAcceptsPinnedForwarderAllowList — положительный путь.
// Держит стражу от вырождения в «отказывать всегда».
func TestValidate_ProductionAcceptsPinnedForwarderAllowList(t *testing.T) {
	if err := forwarderCfg(config.ModeProductionStrict, gatewaySAN, vpcSAN).Validate(); err != nil {
		t.Fatalf("a pinned allow-list must boot, got refusal: %v", err)
	}
}

// TestValidate_DevRefusesAnUnnarrowedCircleWithoutTheOptIn — вне боевого режима
// пустой круг ВОЗМОЖЕН, но только как явный опт-ин. Стража, молчащая вне боевого
// режима, — контроль, чья ветка на локальном стенде не исполняется ни разу.
func TestValidate_DevRefusesAnUnnarrowedCircleWithoutTheOptIn(t *testing.T) {
	err := forwarderCfg(config.ModeDev).Validate()
	if err == nil {
		t.Fatal("dev with an unnarrowed circle and no opt-in must refuse to start")
	}
	if !strings.Contains(err.Error(), forwarderKnobName) {
		t.Fatalf("the refusal must name the knob %q, got: %v", forwarderKnobName, err)
	}
}

// TestValidate_DevToleratesAnUnnarrowedCircleWithTheExplicitOptIn — положительный
// контроль к предыдущему: без него отрицание зеленело бы и на «отказывать всегда».
func TestValidate_DevToleratesAnUnnarrowedCircleWithTheExplicitOptIn(t *testing.T) {
	cfg := forwarderCfg(config.ModeDev)
	cfg.AuthN.TrustAnyForwarder = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("dev with the explicit opt-in must boot (in-process fixtures), got: %v", err)
	}
}

// TestValidate_ProductionIgnoresTheDevOptIn — опт-ин не действует в боевом
// режиме: иначе он был бы ручкой, снимающей защиту на развёрнутом стенде.
func TestValidate_ProductionIgnoresTheDevOptIn(t *testing.T) {
	cfg := forwarderCfg(config.ModeProduction)
	cfg.AuthN.TrustAnyForwarder = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("production must refuse an unnarrowed circle even with the dev opt-in set")
	}
}
