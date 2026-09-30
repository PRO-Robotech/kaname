// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_provider_road_wiring_test.go — КОМПОЗИЦИОННЫЙ КОРЕНЬ на посадке без
// внешнего поставщика дорогу к нему НЕ СТРОИТ (задача kaname#21). Записи
// зеркала его ключей корень не публикует ни на какой посадке: она снята вместе
// с внешним издателем (kaname#361), и привязку «издатель → путь», которая
// отвергает вторую запись, судит пакет публикатора.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СУДИТСЯ, А ЧТО УЖЕ СУДИТСЯ В ДРУГОМ МЕСТЕ
//
// Требование («под own дорога не строится») объявлено СТРОКОЙ таблицы полос и
// проверено там же — `config.ValidateLaneWiring` отвергает старт, когда поле
// провязки говорит «построена». Эти пробы о другом конце: что композиционный
// корень СТАВИТ В ЭТО ПОЛЕ ПРАВДУ и что он действительно не строит.
//
// До правки kaname#21 поле было ЛИТЕРАЛОМ `true`. Литерал не мог покраснеть ни
// при какой посадке, то есть наблюдатель отчитывался о намерении вместо исхода —
// ровно тот класс, ради которого самоотчёт о посадке и заведён.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАЖДОЕ ОТРИЦАНИЕ СТОИТ В ПАРЕ С ПОЛОЖИТЕЛЬНЫМ КОНТРОЛЕМ
//
// Без близнеца «под own не строится» зеленело бы на наблюдателе, который не
// строит НИКОГДА, — то есть на сломанной посадке `external`, где дорога нужна.
package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// roadCfg — минимальная настройка, называющая посадку и слушатель публикатора.
func roadCfg(p config.IdentityProvider, jwksEndpoint string) config.Config {
	cfg := config.Config{}
	cfg.AuthN.Mode = config.ModeProduction
	cfg.AuthN.IdentityProvider = p
	cfg.AuthN.Domain = "kaname.test"
	cfg.AuthN.HydraAdminURL = "https://hydra-admin.kaname.test"
	cfg.APIServer.JWKSProxy.Endpoint = jwksEndpoint
	return cfg
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// ДОРОГА: под `own` не строится, под `external` строится — и достаётся ТОЛЬКО
// ветви построенной посадки (задача kaname#338).
//
// Развилка судится исходом, а не ответом: какая ветвь исполнилась и что она
// получила. Под `own` ветвь с дорогой не исполняется НИ РАЗУ — значит клиента
// без адреса, который прежде уходил потребителям значением, не получает никто.
func TestCompositionRoot_AdminRoadIsBuiltOnlyWhereAProviderExists(t *testing.T) {
	type taken struct {
		built, absent int
		road          *providerAdminRoad
	}
	fork := func(cfg config.Config) taken {
		var got taken
		_, _ = onProviderAdminRoad(cfg, nil,
			func(road *providerAdminRoad) (struct{}, error) {
				got.built++
				got.road = road
				return struct{}{}, nil
			},
			func() (struct{}, error) {
				got.absent++
				return struct{}{}, nil
			})
		return got
	}

	own := fork(roadCfg(config.IdentityProviderOwn, "9097"))
	if own.built != 0 || own.road != nil {
		t.Errorf("под own исполнена ветвь С ДОРОГОЙ (%d раз, клиент %v) — потребитель "+
			"получил дорогу к поставщику, которого на этой посадке нет", own.built, own.road)
	}
	if own.absent != 1 {
		t.Fatalf("под own ветвь без дороги исполнена %d раз, а не один — потребитель "+
			"остался без своего решения", own.absent)
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: под external дорога обязана быть и прийти ветви.
	ext := fork(roadCfg(config.IdentityProviderExternal, "9097"))
	if ext.absent != 0 {
		t.Errorf("под external исполнена ветвь без дороги (%d раз) — потребители ушли бы "+
			"на собственную полосу там, где исполняет чужой поставщик", ext.absent)
	}
	if ext.built != 1 || ext.road == nil || ext.road.BaseURL == "" {
		t.Fatalf("под external дорога НЕ пришла ветви построенной посадки (исполнена %d раз, "+
			"клиент %v) — отрицание выше зеленело бы на развилке, которая не строит никогда",
			ext.built, ext.road)
	}
}

// НАБЛЮДАТЕЛЬ ГОВОРИТ ПРАВДУ О ТОМ, ЧТО КОРЕНЬ СДЕЛАЛ.
func TestObserveLaneWiring_ReportsTheRoadItActuallyBuilt(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger()

	own := observeLaneWiring(ctx, roadCfg(config.IdentityProviderOwn, "9097"), nil, nil, nil, lg)
	if own.ProviderAdminHopBuilt {
		t.Error("под own наблюдатель докладывает построенную дорогу, которой корень не строит")
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: под external факт истинен.
	ext := observeLaneWiring(ctx, roadCfg(config.IdentityProviderExternal, "9097"), nil, nil, nil, lg)
	if !ext.ProviderAdminHopBuilt {
		t.Error("под external дорога не доложена — отрицание выше зеленело бы на " +
			"наблюдателе, отвечающем false всегда")
	}
}
