// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_axis_withdrawn_test.go — ТРЕБОВАНИЯ ПОСАДКИ СУДЯТСЯ НА КАЖДОМ БОЕВОМ
// СТАРТЕ, А НЕ ПО ЗНАЧЕНИЮ КЛЮЧА ПОСАДКИ (kaname#363).
//
// Ось посадки снята: требований «полосы» больше не выбирает никто, и те, что
// прежде предъявлялись посадке `own`, предъявляются всякому боевому старту.
// Опасность снятия — ВАКУУМНЫЙ исход: страж, который раньше пропускал
// необъявленную посадку ранним возвратом («об этом уже отказала проверка
// настройки»), при механической правке остался бы ранним возвратом без
// предмета — и стадия сборки не исполнялась бы вовсе, а зелёное читалось бы как
// «провязано».
//
// Здесь две пробы, по одной на стадию, и у каждой законный близнец:
//
//	сборка     пустая провязка в боевом режиме — отказ по каждой строке;
//	           близнец — полная провязка, тот же режим: отказа нет;
//	настройка  полный боевой профиль без ключа посадки поднимается; тот же
//	           профиль без величин своего входа — отказ называет их и НЕ
//	           называет ключа посадки; близнец — тот же профиль вне боевого
//	           режима: отказа нет.
package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// fullWiring — провязка, на которой каждая строка стадии сборки выполнена:
// подписант, способы входа и сессия человека собраны, каталог прочитан, и
// поднятых им полов полоса предъявить умеет.
func fullWiring() config.LaneWiring {
	return config.LaneWiring{
		OwnMintSignerWired:    true,
		HumanCredentialsWired: true,
		HumanSessionsWired:    true,
		PresentableACRs:       []string{"1", "2"},
		CatalogFloors: config.CatalogFloors{
			Readable: true,
			ByLevel:  map[string]int{"1": 285, "2": 32},
		},
	}
}

// Стадия сборки: боевой режим, посадки в настройке нет вовсе — строки
// исполняются все, без раннего возврата.
func TestLaneWiringIsJudgedOnEveryProductionStart(t *testing.T) {
	var cfg config.Config
	cfg.AuthN.Mode = config.ModeProduction

	err := config.ValidateLaneWiring(cfg, config.LaneWiring{})
	if err == nil {
		t.Fatal("ValidateLaneWiring() = nil на пустой провязке в боевом режиме: стадия сборки не " +
			"исполнилась, и процесс поднялся бы без подписанта, без входа человека и без каталога")
	}
	msg := err.Error()
	wants := []string{
		"signer is not wired",
		"no store of our own human sign-in methods",
		"no store of our own human session",
		"permission catalog could not be read",
	}
	named := 0
	for _, want := range wants {
		if !strings.Contains(msg, want) {
			t.Errorf("отказ стадии сборки не называет строку %q:\n%s", want, msg)
			continue
		}
		named++
	}
	if strings.Contains(msg, "identity-provider") {
		t.Errorf("отказ стадии сборки называет снятый ключ посадки — оператор пошёл бы объявлять "+
			"ключ, которого нет:\n%s", msg)
	}
	t.Logf("перепись: строк стадии сборки названо %d из %d ожидаемых", named, len(wants))
}

// Законный близнец: та же посадка, провязка полная — отказа нет. Без него
// красное выше означало бы «стадия отказывает всегда».
func TestFullLaneWiringPassesOnProductionStart(t *testing.T) {
	var cfg config.Config
	cfg.AuthN.Mode = config.ModeProduction
	if err := config.ValidateLaneWiring(cfg, fullWiring()); err != nil {
		t.Fatalf("полная провязка в боевом режиме обязана проходить, получено: %v", err)
	}
}

// loadProfileWithoutPostureKey собирает профиль из таблицы обязательных
// величин ТЕМ путём, каким его подаёт оператор, — переменными окружения, — и
// загружает его. Ключа посадки в профиле нет; строки, чей ключ начинается с
// omitPrefix, не подаются (пустой — подаются все).
//
// Собирается только из того, что переживает снятие оси (ключ, переменная,
// образец строки): проба обязана собираться и до правки, и после, иначе её
// красное было бы красным компиляции, а не предмета.
func loadProfileWithoutPostureKey(t *testing.T, mode, omitPrefix string) config.Config {
	t.Helper()
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 && strings.HasPrefix(kv[:i], "KANAME_") {
			t.Setenv(kv[:i], "")
			if err := os.Unsetenv(kv[:i]); err != nil {
				t.Fatalf("переменная %s не снята: %v", kv[:i], err)
			}
		}
	}
	t.Setenv("KANAME_AUTHN__MODE", mode)
	supplied := 0
	for _, s := range config.RequiredSettings {
		if s.Key == retiredPostureKey {
			continue
		}
		// Строки таблицы границ почты (Р8) судятся БЕЗУСЛОВНО, в любом режиме, и
		// требованиями своего входа не являются, хотя часть их ключей лежит под
		// той же приставкой: они подаются всегда, иначе отказ dev-близнеца
		// пришёл бы от них, а не от предмета пробы.
		if omitPrefix != "" && strings.HasPrefix(s.Key, omitPrefix) && !isMailBoundKey(s.Key) {
			continue
		}
		t.Setenv(s.Env, s.Sample)
		supplied++
	}
	if supplied == 0 {
		t.Fatal("из таблицы обязательных величин не подано ни одной — профиль пуст, и вердикт был бы о пустоте")
	}
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("профиль без ключа посадки не загрузился — это «не выполнилось», а не вердикт: %v", err)
	}
	t.Logf("перепись профиля: величин подано %d · режим %s · не подано по приставке %q", supplied, mode, omitPrefix)
	return cfg
}

// Стадия настройки, положительная половина: полный боевой профиль БЕЗ ключа
// посадки поднимается — ключ больше ничего не выбирает и ничего не требует.
func TestProductionProfileWithoutAPostureKeyPassesTheStart(t *testing.T) {
	cfg := loadProfileWithoutPostureKey(t, "production", "")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("полный боевой профиль без ключа посадки обязан проходить проверку настройки, получено:\n%v", err)
	}
}

// Стадия настройки, отрицательная половина: тот же профиль без величин своего
// входа. Отказ называет их — то есть требования, прежде предъявлявшиеся посадке
// `own`, предъявлены всякому боевому старту, — и ключа посадки НЕ называет.
// Отличие от положительной половины ровно одно — величины своего входа не поданы.
func TestProductionStartJudgesOwnLaneRowsWithoutAPostureKey(t *testing.T) {
	cfg := loadProfileWithoutPostureKey(t, "production", "authn.login.")

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil на боевом профиле без величин своего входа")
	}
	msg := err.Error()
	wants := []string{
		"authn.login.session-ttl",
		"authn.login.password-min-length",
		"authn.login.verification-code-attempts",
	}
	named := 0
	for _, want := range wants {
		if !strings.Contains(msg, want) {
			t.Errorf("отказ боевого профиля без величин своего входа не называет %q — требование "+
				"своего входа не предъявлено:\n%s", want, msg)
			continue
		}
		named++
	}
	if strings.Contains(msg, "identity-provider") {
		t.Errorf("отказ боевого профиля называет снятый ключ посадки:\n%s", msg)
	}
	t.Logf("перепись: величин своего входа названо %d из %d ожидаемых", named, len(wants))
}

// Законный близнец отрицательной половины: тот же профиль вне боевого режима —
// требований своего входа нет. Отличие ровно одно — режим.
func TestDevStartCarriesNoOwnLaneRequirement(t *testing.T) {
	cfg := loadProfileWithoutPostureKey(t, "dev", "authn.login.")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("профиль без величин своего входа вне боевого режима обязан проходить проверку "+
			"настройки, получено: %v", err)
	}
}

// isMailBoundKey — ключ строки таблицы границ почты (config.MailBounds).
func isMailBoundKey(key string) bool {
	for _, b := range config.MailBounds {
		if b.Key == key {
			return true
		}
	}
	return false
}
