// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_wire_guard_injection_test.go — доказательство падучести В ОБЕ
// СТОРОНЫ (задачи `kacho#2573`, `kaname#21`).
//
// Каждая ось меняет РОВНО ОДИН факт против своего положительного близнеца:
// иначе неизвестно, какой из двух дал красное, и вердикт недействителен.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// scanWire — разбор одного синтетического файла настройками гейта.
func scanWire(t *testing.T, src string) ([]check.ProviderRoadWireMethod, check.ProviderRoadWireCensus) {
	t.Helper()
	ms, census, err := check.ScanProviderRoadWireMethods("internal/clients/x.go", []byte(src),
		providerRoadClientType, providerRoadAddressField, providerRoadGuardName,
		providerRoadGuardExempt)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	return ms, census
}

// TestProviderRoadWire_RedOnAMethodThatNeverAsks — ИНЪЕКЦИЯ: метод уходит на
// провод, стража не спросив.
func TestProviderRoadWire_RedOnAMethodThatNeverAsks(t *testing.T) {
	t.Parallel()
	src := `package clients

func (c *HydraAdminClient) TrustGrant(ctx context.Context, id string) error {
	url := c.BaseURL + "/admin/trust/grants"
	return c.post(ctx, url)
}
`
	ms, census := scanWire(t, src)
	unguarded := check.UnguardedProviderRoadWireMethods(ms)
	if len(unguarded) != 1 {
		t.Fatalf("метод БЕЗ стража не стал находкой: %d (осмотрено %+v)", len(unguarded), census)
	}
	if unguarded[0].Method != "TrustGrant" {
		t.Errorf("находка не называет метод: %+v", unguarded[0])
	}
	if unguarded[0].GuardLine != 0 {
		t.Errorf("страж не спрошен, а находка утверждает строку %d", unguarded[0].GuardLine)
	}
	if unguarded[0].AddressLine != 4 {
		t.Errorf("находка не называет строку касания адреса: %+v", unguarded[0])
	}
}

// TestProviderRoadWire_RedOnAGuardAskedTooLate — ИНЪЕКЦИЯ ОТДЕЛЬНОЙ ОСИ: страж
// спрошен, но ПОСЛЕ того как запрос собран.
//
// Ось не декоративная: это та же ошибка, что дала имя задаче, — решение
// принимается после того, как построено то, о чём решают.
func TestProviderRoadWire_RedOnAGuardAskedTooLate(t *testing.T) {
	t.Parallel()
	src := `package clients

func (c *HydraAdminClient) TrustGrant(ctx context.Context, id string) error {
	url := c.BaseURL + "/admin/trust/grants"
	if !c.roadIsBuilt() {
		return c.refuseAbsentRoad("trust-grant")
	}
	return c.post(ctx, url)
}
`
	ms, _ := scanWire(t, src)
	unguarded := check.UnguardedProviderRoadWireMethods(ms)
	if len(unguarded) != 1 {
		t.Fatalf("страж, спрошенный ПОСЛЕ касания адреса, находкой не стал: %d", len(unguarded))
	}
	if unguarded[0].GuardLine == 0 {
		t.Errorf("находка не называет строку стража: %+v", unguarded[0])
	}
	if unguarded[0].GuardLine <= unguarded[0].AddressLine {
		t.Errorf("порядок прочитан неверно: %+v", unguarded[0])
	}
}

// TestProviderRoadWire_SilentOnAGuardAskedFirst — ЗАКОННЫЙ БЛИЗНЕЦ к обеим
// инъекциям выше: тот же метод, страж первым оператором.
func TestProviderRoadWire_SilentOnAGuardAskedFirst(t *testing.T) {
	t.Parallel()
	src := `package clients

func (c *HydraAdminClient) TrustGrant(ctx context.Context, id string) error {
	if !c.roadIsBuilt() {
		return c.refuseAbsentRoad("trust-grant")
	}
	url := c.BaseURL + "/admin/trust/grants"
	return c.post(ctx, url)
}
`
	ms, census := scanWire(t, src)
	if len(ms) != 1 {
		t.Fatalf("метод, уходящий на провод, не увиден вовсе: %d — тогда отрицания выше "+
			"зеленели бы на распознавателе, не видящем ничего", len(ms))
	}
	if !ms[0].Guarded() {
		t.Fatalf("ВЕРНЫЙ метод объявлен находкой: %+v — гейт краснел бы на исправном коде "+
			"и был бы отключён первым", ms[0])
	}
	if census.AddressTouching != 1 || census.GuardCalls != 1 {
		t.Errorf("перепись разошлась с разбором: %+v", census)
	}
}

// TestProviderRoadWire_SilentOnAMethodThatNeverTouchesTheAddress — ЗАКОННЫЙ
// БЛИЗНЕЦ: метод типа, на провод не уходящий. Он осмотрен, но предметом не
// является — и обязан быть виден переписи, иначе «трогающих ноль» неотличимо
// от «методов не найдено».
func TestProviderRoadWire_SilentOnAMethodThatNeverTouchesTheAddress(t *testing.T) {
	t.Parallel()
	src := `package clients

func (c *HydraAdminClient) WithRoadObserver(obs ProviderRoadObserver) *HydraAdminClient {
	c.roadObserver = obs
	return c
}
`
	ms, census := scanWire(t, src)
	if len(ms) != 0 {
		t.Errorf("метод, адреса не трогающий, объявлен уходящим на провод: %+v", ms)
	}
	if census.Methods != 1 {
		t.Errorf("метод не засчитан переписью: %+v", census)
	}
	if census.AddressTouching != 0 {
		t.Errorf("касание адреса насчитано там, где его нет: %+v", census)
	}
}

// TestProviderRoadWire_SilentOnTheGuardItself — ЗАКОННЫЙ БЛИЗНЕЦ: сам страж
// судит ПО АДРЕСУ, поэтому спросить себя не может. Без освобождения гейт
// краснел бы на собственном держателе.
func TestProviderRoadWire_SilentOnTheGuardItself(t *testing.T) {
	t.Parallel()
	src := `package clients

func (c *HydraAdminClient) roadIsBuilt() bool {
	return c != nil && c.BaseURL != ""
}
`
	ms, census := scanWire(t, src)
	if len(ms) != 0 {
		t.Errorf("сам страж объявлен находкой: %+v — гейт краснел бы на своём держателе", ms)
	}
	if census.Methods != 1 {
		t.Errorf("страж не засчитан переписью методов: %+v", census)
	}
}

// TestProviderRoadWire_SilentOnAnotherTypeWithTheSameFieldName — ЗАКОННЫЙ
// БЛИЗНЕЦ: разбор судит по ТИПУ ПОЛУЧАТЕЛЯ, а не по имени поля.
//
// Ось несущая: `BaseURL` — имя обычное, оно стоит у клиентов набора ключей, у
// обмена токена и у соседних служб. Гейт, судящий по имени поля, краснел бы на
// каждом из них — и был бы снят как непонятный.
func TestProviderRoadWire_SilentOnAnotherTypeWithTheSameFieldName(t *testing.T) {
	t.Parallel()
	src := `package clients

func (c *JWKSMirrorClient) Fetch(ctx context.Context) error {
	return c.get(ctx, c.BaseURL+"/.well-known/jwks.json")
}
`
	ms, census := scanWire(t, src)
	if len(ms) != 0 {
		t.Errorf("метод ЧУЖОГО типа объявлен находкой: %+v — гейт судит имя поля, а не тип", ms)
	}
	if census.Methods != 0 {
		t.Errorf("метод чужого типа засчитан переписью: %+v", census)
	}
}

// TestProviderRoadWire_SilentOnAConstructorSettingTheField — ЗАКОННЫЙ БЛИЗНЕЦ:
// строитель заполняет поле адреса в составном литерале. Он функция, а не метод,
// и стража спросить не может by construction.
func TestProviderRoadWire_SilentOnAConstructorSettingTheField(t *testing.T) {
	t.Parallel()
	src := `package clients

func NewHydraAdminClientWithCA(baseURL, token, caFile string) (*HydraAdminClient, error) {
	return &HydraAdminClient{BaseURL: strings.TrimRight(baseURL, "/")}, nil
}
`
	ms, census := scanWire(t, src)
	if len(ms) != 0 {
		t.Errorf("строитель объявлен уходящим на провод: %+v", ms)
	}
	if census.Methods != 0 {
		t.Errorf("функция засчитана методом получателя: %+v", census)
	}
}

// TestProviderRoadWire_EmptyInputIsNotAVerdict — пустой файл вердикта не даёт.
func TestProviderRoadWire_EmptyInputIsNotAVerdict(t *testing.T) {
	t.Parallel()
	ms, census := scanWire(t, "package clients\n")
	if len(ms) != 0 || census.Methods != 0 {
		t.Fatalf("пустой файл дал непустой разбор: %d, %+v", len(ms), census)
	}
}
