// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_provider_road_wiring_test.go — КОМПОЗИЦИОННЫЙ КОРЕНЬ на посадке без
// внешнего поставщика дорогу к нему НЕ СТРОИТ и запись зеркала его ключей НЕ
// ПУБЛИКУЕТ (задача kaname#21).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СУДИТСЯ, А ЧТО УЖЕ СУДИТСЯ В ДРУГОМ МЕСТЕ
//
// Требование («под own дорога не строится») объявлено СТРОКОЙ таблицы полос и
// проверено там же — `config.ValidateLaneWiring` отвергает старт, когда поле
// провязки говорит «построена». Эти пробы о другом конце: что композиционный
// корень СТАВИТ В ЭТО ПОЛЕ ПРАВДУ и что он действительно не строит.
//
// До этой правки оба поля были ЛИТЕРАЛАМИ `true`. Литерал не мог покраснеть ни
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

// ДОРОГА: под `own` не строится, под `external` строится.
func TestCompositionRoot_AdminRoadIsBuiltOnlyWhereAProviderExists(t *testing.T) {
	own := mustProviderAdminClient(roadCfg(config.IdentityProviderOwn, "9097"), nil)
	if own == nil {
		t.Fatal("mustProviderAdminClient() = nil под own; потребителям нужен объект, " +
			"отказывающий по имени, а не пустой указатель")
	}
	if own.BaseURL != "" {
		t.Errorf("под own дорога построена на адрес %q — а внешнего поставщика "+
			"на этой посадке нет вовсе", own.BaseURL)
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: под external дорога обязана быть.
	ext := mustProviderAdminClient(roadCfg(config.IdentityProviderExternal, "9097"), nil)
	if ext == nil || ext.BaseURL == "" {
		t.Fatal("под external дорога НЕ построена — отрицание выше зеленело бы на " +
			"корне, который не строит никогда")
	}
}

// НАБЛЮДАТЕЛЬ ГОВОРИТ ПРАВДУ О ТОМ, ЧТО КОРЕНЬ СДЕЛАЛ.
func TestObserveLaneWiring_ReportsTheRoadItActuallyBuilt(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger()

	own := observeLaneWiring(ctx, roadCfg(config.IdentityProviderOwn, "9097"), nil, nil, lg)
	if own.ProviderAdminHopBuilt {
		t.Error("под own наблюдатель докладывает построенную дорогу, которой корень не строит")
	}
	if own.ProviderKeySetMirrorPublished {
		t.Error("под own наблюдатель докладывает опубликованное зеркало чужих ключей, " +
			"которого публикатор не несёт")
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: под external оба факта истинны.
	ext := observeLaneWiring(ctx, roadCfg(config.IdentityProviderExternal, "9097"), nil, nil, lg)
	if !ext.ProviderAdminHopBuilt {
		t.Error("под external дорога не доложена — отрицание выше зеленело бы на " +
			"наблюдателе, отвечающем false всегда")
	}
	if !ext.ProviderKeySetMirrorPublished {
		t.Error("под external зеркало не доложено — то же самое")
	}
}

// СЛУШАТЕЛЬ ПУБЛИКАТОРА ВЫКЛЮЧЕН ⇒ ЗЕРКАЛА НЕТ, И ЭТО ТРЕТЬЯ ОСЬ.
//
// Литерал `true` лгал и здесь, а не только под own: при незаданном слушателе
// публикатора запись зеркала не добавляется НИ НА КАКОЙ посадке — блок публикации
// не исполняется вовсе. То есть наблюдатель докладывал опубликованным то, чего
// не существует, на стенде, который публикатора не поднимал.
func TestObserveLaneWiring_NoPublisherListenerMeansNoMirror(t *testing.T) {
	w := observeLaneWiring(context.Background(),
		roadCfg(config.IdentityProviderExternal, ""), nil, nil, quietLogger())
	if w.ProviderKeySetMirrorPublished {
		t.Error("слушателя публикатора нет, а зеркало доложено опубликованным: " +
			"наблюдатель отчитывается о намерении вместо исхода")
	}
}
