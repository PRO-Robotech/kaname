// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// hooks_lane_posture_test.go — ХУКИ ПОСТАВЩИКА ЛИЧНОСТИ СОБИРАЮТСЯ ТОЛЬКО ТАМ,
// ГДЕ ПОСТАВЩИК ЕСТЬ (kaname#360).
//
// Под `authn.identity-provider=own` внешнего поставщика нет: у хуков Hydra
// (token, refresh) и Kratos (provision, recovery) нет вызывающего, и держать их
// в работе значит держать открытыми маршруты, которые обслуживают никого. Под
// `external` полоса та же, что прежде, — все четыре маршрута отвечают.
//
// Решение берётся у ЕДИНСТВЕННОГО предиката посадки
// (`AuthNConfig.HasExternalIdentityProvider`), которым корень решает и дорогу к
// поставщику, и запись зеркала его ключей: второй предикат разошёлся бы с ними
// ровно на посадке, ради которой служба выносится отдельным продуктом.

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/servicecontract"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// hooksLaneOf — поверхность вебхуков, собранная построителем корня под
// названной посадкой, и сколько раз корень собрал полосу хуков.
func hooksLaneOf(t *testing.T, p config.IdentityProvider, tlsCfg *tls.Config) (servicecontract.SurfaceDescriptor, int) {
	t.Helper()
	cfg := roadCfg(p, "9097")
	cfg.AuthN.HooksHTTPEndpoint = "tcp://0.0.0.0:9092"
	built := 0
	desc, err := hooksLaneSurface(cfg, servicecontract.ModeProduction, quietLogger(), tlsCfg, func() http.Handler {
		built++
		return buildHooksMux(nil, nil, nil, nil, metrics.NewRegistry(), cfg, quietLogger())
	})
	if err != nil {
		t.Fatalf("посадка %s: построитель поверхности вебхуков отказал: %v", p, err)
	}
	return desc, built
}

// Под own НЕ ОТВЕЧАЕТ НИ ОДИН путь хуков: слушателя нет, полоса не собрана.
func TestHooksLaneIsNotAssembledWhereNoProviderExists(t *testing.T) {
	desc, built := hooksLaneOf(t, config.IdentityProviderOwn, &tls.Config{MinVersion: tls.VersionTLS13})
	if built != 0 {
		t.Errorf("под own корень собрал полосу хуков %d раз(а): у Hydra и Kratos на этой посадке нет "+
			"вызывающего, а маршруты в работе", built)
	}
	if desc.Enabled() {
		t.Errorf("под own слушатель вебхуков поднимается — его порт держит в работе полосу, " +
			"которую обслуживать некому")
	}
	if _, given := desc.Spec().Addr.Get(); given {
		t.Errorf("под own адрес слушателя вебхуков объявлен значением, а не отсутствием с причиной")
	}
	if why, ok := desc.Spec().Addr.NotApplicableBecause(); !ok || why == "" {
		t.Errorf("под own отсутствие слушателя вебхуков не названо причиной — оператор не отличит " +
			"решение от недосмотра")
	}
	if desc.Spec().Handler != nil {
		t.Errorf("под own у поверхности вебхуков есть обработчик — ответить на /iam/v1/hooks/* ему есть чем")
	}
}

// Законный близнец: под external отвечают ВСЕ ЧЕТЫРЕ маршрута полосы, и
// транспорт доезжает до объявления тем, который передал корень.
func TestHooksLaneAnswersEveryRouteWhereTheProviderExists(t *testing.T) {
	given := &tls.Config{MinVersion: tls.VersionTLS13}
	desc, built := hooksLaneOf(t, config.IdentityProviderExternal, given)
	if built != 1 {
		t.Fatalf("под external корень собрал полосу хуков %d раз(а), ожидался один", built)
	}
	if !desc.Enabled() {
		t.Fatal("под external слушатель вебхуков не поднимается — поставщику некуда звать хуки")
	}
	if desc.Spec().TLS != given {
		t.Errorf("транспорт, собранный корнем, не доехал до объявления поверхности вебхуков")
	}
	routes := 0
	for _, r := range handlerinternal.Routes() {
		rec := httptest.NewRecorder()
		desc.Spec().Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/"+r, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("под external маршрут /iam/v1/hooks/%s не отвечает (404)", r)
		}
		routes++
	}
	if routes != 4 {
		t.Fatalf("производитель перечня назвал %d маршрутов полосы, ожидались четыре", routes)
	}
	t.Logf("перепись: маршрутов полосы %d · отвечают под external все", routes)
}

// ТРАНСПОРТ СУДИТСЯ У ТОГО СЛУШАТЕЛЯ, КОТОРЫЙ ПОДНИМАЕТСЯ. Под own слушателя
// вебхуков нет, и страж транспорта HTTP-рёбер не вправе требовать TLS у двери,
// которой не будет: иначе посадка own без сертификата несуществующего
// слушателя не стартует. Законный близнец — external с той же посадкой
// транспорта: отказ называет слушатель вебхуков.
func TestHooksEdgeTransportIsJudgedOnlyWhereTheListenerIsRaised(t *testing.T) {
	for _, c := range []struct {
		p       config.IdentityProvider
		refused bool
	}{
		{config.IdentityProviderOwn, false},
		{config.IdentityProviderExternal, true},
	} {
		cfg := roadCfg(c.p, "9097")
		cfg.AuthN.HooksHTTPEndpoint = "tcp://0.0.0.0:9092"
		_, err := requireHTTPEdgeTLS(true, iamHTTPEdges(hooksListenAddress(cfg), "", "", "", "", config.MTLSConfig{}))
		refusedHooks := err != nil && strings.Contains(err.Error(), "identity-provider hooks")
		if refusedHooks != c.refused {
			t.Errorf("посадка %s: страж транспорта отказал слушателю вебхуков=%v, ожидалось %v (%v)",
				c.p, refusedHooks, c.refused, err)
		}
	}
}
