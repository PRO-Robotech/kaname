// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provideradmincredential_test.go — доказательство того, что страж соседнего
// файла СПОСОБЕН упасть, и падает ровно на половине пары.
//
// У каждого отрицания стоит ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся ОДНИМ фактом.
package main

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// adminHopStub — посадка контура, поданная стражу без сборки из окружения.
type adminHopStub struct {
	url     string
	auth    string
	envName string
	token   string
}

func (s adminHopStub) DeclaredHydraAdminURL() string { return s.url }
func (s adminHopStub) ProviderAdminAuthValue() string {
	return strings.ToLower(strings.TrimSpace(s.auth))
}
func (s adminHopStub) HydraAdminTokenEnvName() string { return s.envName }
func (s adminHopStub) ResolveHydraAdminToken() string { return s.token }

func TestProviderAdminPair_BearerWithoutACredentialRefusesTheStart(t *testing.T) {
	err := requireProviderAdminCredentialPair(adminHopStub{
		url: "https://hydra-admin.example.invalid:4445", auth: config.ProviderAdminAuthBearer,
		envName: "KANAME_HYDRA_ADMIN_TOKEN", token: "",
	})
	if err == nil {
		t.Fatal("половина пары принята: адрес назван, предъявитель объявлен и не пришёл")
	}
	// Отказ обязан назвать ТРИ величины: чинится это в трёх разных местах.
	for _, want := range []string{"provider-admin-auth", "KANAME_HYDRA_ADMIN_TOKEN", "hydra-admin.example.invalid"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("отказ не называет %q: %v", want, err)
		}
	}
}

func TestProviderAdminPair_BearerWithACredentialIsSilent(t *testing.T) {
	// ЗАКОННЫЙ БЛИЗНЕЦ отрицания выше: ровно один факт отличия — предъявитель пришёл.
	if err := requireProviderAdminCredentialPair(adminHopStub{
		url: "https://hydra-admin.example.invalid:4445", auth: config.ProviderAdminAuthBearer,
		envName: "KANAME_HYDRA_ADMIN_TOKEN", token: "не-настоящий-предъявитель",
	}); err != nil {
		t.Fatalf("полная пара отвергнута: %v", err)
	}
}

func TestProviderAdminPair_DeclaredNoneIsSilent(t *testing.T) {
	// Оператор ВЫСКАЗАЛСЯ: его поставщик административный порт не
	// аутентифицирует. Это утверждение о его установке, и страж его принимает.
	if err := requireProviderAdminCredentialPair(adminHopStub{
		url: "https://hydra-admin.example.invalid:4445", auth: config.ProviderAdminAuthNone,
		envName: "KANAME_HYDRA_ADMIN_TOKEN",
	}); err != nil {
		t.Fatalf("объявленный none отвергнут: %v", err)
	}
}

func TestProviderAdminPair_UndeclaredChoiceIsSilent(t *testing.T) {
	// ОБЛАСТЬ, а не послабление: незаданная ручка означает «оператор не
	// высказывался», и прежнее поведение остаётся. Потребовать высказывания
	// здесь значило бы не пустить в старт каждый существующий стенд — то есть
	// завести объявленную и неисполнимую посадку вместо той, которую чиним.
	// Высказаться требует ЧАРТ (offered-профиль объявляет ручку непустой).
	if err := requireProviderAdminCredentialPair(adminHopStub{
		url: "https://hydra-admin.example.invalid:4445", auth: "",
		envName: "KANAME_HYDRA_ADMIN_TOKEN",
	}); err != nil {
		t.Fatalf("незаданный выбор отвергнут — область стража шире объявленной: %v", err)
	}
}

func TestProviderAdminPair_NoAddressIsSilent(t *testing.T) {
	// Контура нет — судить нечего. Тот же порядок, что у соседних стражей рёбер.
	if err := requireProviderAdminCredentialPair(adminHopStub{
		url: "", auth: config.ProviderAdminAuthBearer, envName: "KANAME_HYDRA_ADMIN_TOKEN",
	}); err != nil {
		t.Fatalf("страж высказался о контуре, которого нет: %v", err)
	}
}

func TestProviderAdminPair_UnknownValueRefusesTheStart(t *testing.T) {
	// Опечатка в ручке безопасности, прочитанная как «не нужен», дала бы ровно
	// то состояние, ради которого страж заведён, и выглядела бы настроенной.
	err := requireProviderAdminCredentialPair(adminHopStub{
		url: "https://hydra-admin.example.invalid:4445", auth: "Bearer-token",
		envName: "KANAME_HYDRA_ADMIN_TOKEN",
	})
	if err == nil {
		t.Fatal("значение вне закрытого словаря принято")
	}
	if !strings.Contains(err.Error(), "bearer | none") {
		t.Fatalf("отказ не называет закрытого словаря: %v", err)
	}
}

func TestProviderAdminPair_ValueIsReadCaseAndSpaceInsensitively(t *testing.T) {
	// Законный близнец предыдущего: то же слово в другом регистре — НЕ опечатка.
	// Без этой пары страж отвергал бы верное значение, и его сняли бы первым.
	if err := requireProviderAdminCredentialPair(adminHopStub{
		url: "https://hydra-admin.example.invalid:4445", auth: "  NONE ",
		envName: "KANAME_HYDRA_ADMIN_TOKEN",
	}); err != nil {
		t.Fatalf("верное значение в другом регистре отвергнуто: %v", err)
	}
}
