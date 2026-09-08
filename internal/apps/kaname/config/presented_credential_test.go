// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// presented_credential_test.go — сценарии KAN-BOOT-01 и KAN-BOOT-02 приёмки
// KAN-AUTHN-1 (задача продукта #2077).
//
// Единица наблюдения — ОПЕРАТОР чужого облака: он видит отказ старта и его
// текст, и больше ничего. Поэтому здесь утверждается ровно то, что он видит:
// стартует ли служба, названы ли ключи настройки и не назвал ли отказ значения.
package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestKAN_BOOT_01_EnabledWithoutMaterialRefusesTheStart — приём включён,
// величины, без которых у него нет предмета, не заданы.
//
// Отказы приходят ВМЕСТЕ, а не по одному за перезапуск: оператор, чинящий
// настройку по одному отказу на попытку, платит полным циклом подъёма за каждую
// строку.
func TestKAN_BOOT_01_EnabledWithoutMaterialRefusesTheStart(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	cfg.AuthN.PresentedCredential = config.PresentedCredentialConfig{Enabled: true}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil; приём включён, а материала нет — старт обязан быть отвергнут")
	}
	msg := err.Error()

	for _, setting := range []string{
		"authn.presented-credential.audience",
		"authn.presented-credential.revocation-cache-ttl",
	} {
		if !strings.Contains(msg, setting) {
			t.Errorf("отказ обязан назвать ключ настройки %s, получено: %q", setting, msg)
		}
	}
	// Обе строки в ОДНОМ отказе: иначе вторая обнаружится только на следующей
	// попытке подъёма.
	if !strings.Contains(msg, "audience") || !strings.Contains(msg, "revocation-cache-ttl") {
		t.Errorf("отказы пришли не вместе: %q", msg)
	}
}

// TestKAN_BOOT_01_RefusalNamesTheKnobAndNeverItsContent — служба называет ИМЯ
// ручки и никогда её содержимое: текст отказа читает оператор, но попадает он в
// журнал подъёма, а туда значения настройки не идут.
func TestKAN_BOOT_01_RefusalNamesTheKnobAndNeverItsContent(t *testing.T) {
	const secretish = "kaname-public-DO-NOT-PRINT"

	cfg := laneCfg(config.IdentityProviderOwn)
	cfg.AuthN.PresentedCredential = config.PresentedCredentialConfig{
		Enabled:  true,
		Audience: secretish,
		// Единственный изменённый факт против годного профиля: окно отзыва
		// сверх объявленного потолка.
		RevocationCacheTTL: 24 * time.Hour,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil; окно отзыва сверх потолка обязано отвергнуть старт")
	}
	if strings.Contains(err.Error(), secretish) {
		t.Errorf("отказ напечатал значение настройки: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "authn.presented-credential.revocation-cache-ttl") {
		t.Errorf("отказ обязан назвать ключ настройки, получено: %q", err.Error())
	}
}

// TestKAN_BOOT_01_EnabledWithoutOwnMintingRefusesTheStart — приём включён при
// выключенной своей чеканке.
//
// Читатель проверяет подпись СОБСТВЕННЫМ реестром ключей, и без чеканки реестра
// нет вовсе: каждое предъявление отвергалось бы, и отвергалось бы по причине,
// которую снаружи не видно.
func TestKAN_BOOT_01_EnabledWithoutOwnMintingRefusesTheStart(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	cfg.AuthN.TokenSigning.Enabled = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil; приём предъявленного без своей чеканки обязан отвергнуть старт")
	}
	if !strings.Contains(err.Error(), "authn.token-signing.enabled is false") {
		t.Errorf("отказ обязан назвать выключенную чеканку, получено: %q", err.Error())
	}
}

// TestKAN_BOOT_02_MaterialDeclaredLetsTheStartThrough — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ
// KAN-BOOT-01, отличающийся ровно заданными величинами.
//
// Без него «отказывает в старте» зеленело бы на страже, отвергающем любой
// профиль.
func TestKAN_BOOT_02_MaterialDeclaredLetsTheStartThrough(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; профиль с объявленным материалом обязан подниматься", err)
	}
	if !cfg.AuthN.PresentedCredential.Enabled {
		t.Fatal("положительный контроль собран с ВЫКЛЮЧЕННЫМ приёмом — он не о том профиле")
	}
}

// TestKAN_BOOT_02_DisabledLaneRequiresNothing — под посадкой внешнего
// поставщика выключенный приём требований не предъявляет: страж, требующий
// того, чем не пользуются, — отказ в старте без предмета.
func TestKAN_BOOT_02_DisabledLaneRequiresNothing(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderExternal)
	cfg.AuthN.PresentedCredential = config.PresentedCredentialConfig{}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; выключенный приём не обязан требовать своих величин", err)
	}
}

// TestKAN_BOOT_01_WindowCeilingIsTheTokenLifetimeNotAConstant — потолок окна
// отзыва ВЫЧИСЛЯЕТСЯ из срока выпускаемого токена, а не выбирается константой.
//
// Окно, дотягивающее до срока токена, окном быть перестаёт: отозванное
// удостоверение истечёт раньше, чем кеш о нём забудет, и чтение отзыва на
// предъявлении станет неотличимо от его отсутствия — МОЛЧА, потому что ряд
// «отвергнуто» не вырастет.
//
// Утверждение двустороннее: то же самое окно при ДЛИННОМ токене проходит.
// Односторонняя проба зеленела бы на страже, отвергающем любое окно.
func TestKAN_BOOT_01_WindowCeilingIsTheTokenLifetimeNotAConstant(t *testing.T) {
	const window = 30 * time.Second

	withTokenTTL := func(ttl time.Duration) config.Config {
		cfg := laneCfg(config.IdentityProviderOwn)
		cfg.AuthN.PresentedCredential.RevocationCacheTTL = window
		cfg.AuthN.ClientToken.TokenTTL = ttl
		return cfg
	}

	// Токен живёт ДОЛЬШЕ окна — окно осмысленно.
	if err := withTokenTTL(15 * time.Minute).Validate(); err != nil {
		t.Fatalf("окно %s при сроке токена 15m обязано проходить, иначе отрицание ниже "+
			"вакуумно: %v", window, err)
	}

	// Отличие ровно одно: токен живёт КОРОЧЕ окна.
	err := withTokenTTL(10 * time.Second).Validate()
	if err == nil {
		t.Fatal("окно отзыва длиннее срока токена принято — чтение отзыва на предъявлении " +
			"стало бы неотличимо от его отсутствия, и ни один измеритель этого не показал бы")
	}
	if !strings.Contains(err.Error(), "authn.presented-credential.revocation-cache-ttl") {
		t.Errorf("отказ обязан назвать ключ настройки, получено: %q", err.Error())
	}
}
