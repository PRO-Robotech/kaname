// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// mtls_rest_upstream_test.go — страж УДОСТОВЕРЕНИЯ, которым собственный
// REST-фронт представляется собственному слушателю (#2479).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ПОЛОВИНА ПАРЫ ХУЖЕ ОТСУТСТВИЯ ОБЕИХ
//
// Удостоверение объявлено включённым, а сертификата либо ключа нет: посадка
// ВЫГЛЯДИТ настроенной, и ровно поэтому отказ приходит не при старте, а на
// КАЖДОМ запросе — слушатель отвергает клиента без сертификата, и снаружи
// исправная служба читается как недоступная. Тот же класс с третьей стороны:
// набор корней пуст — фронту нечем проверить СЕРВЕРА, и соединение либо не
// состоится, либо состоится без проверки.
//
// Страж написан против этого класса и до #2479 не был покрыт НИ ОДНИМ
// утверждением: единственные две строки дерева, называвшие эту величину, читают
// имя URI из листа и о стráже не высказываются вовсе. То есть свойство держалось
// вниманием — а страж, потерявший способность отказывать, на исправной посадке
// выглядит РОВНО ТАК ЖЕ, как работающий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ТАБЛИЦА, А НЕ ТРИ УТВЕРЖДЕНИЯ
//
// Половин у пары две, и якорь третий; проверять их порознь значит оставить
// перекрёстные случаи (только ключ · только сертификат) невыраженными. Таблица
// перечисляет ПЯТЬ миров, каждый отличается от законного близнеца ровно одним
// фактом, и в каждом сказано, какие отказы обязаны прийти И какие обязаны НЕ
// прийти. Односторонняя проба зеленела бы на стráже, отвергающем всё.
//
// Отрицательный контроль стоит первым намеренно: полная пара обязана молчать.
// Без него «отказ пришёл» доказывало бы лишь то, что страж краснеет всегда.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcclient"
)

// restUpstreamOnly — посадка, где включено РОВНО одно ребро: удостоверение
// исходящего запроса собственного фронта. Все серверные рёбра выключены, чтобы
// в вердикт не приходили чужие отказы: инъекция обязана ронять только
// проверяемое.
func restUpstreamOnly(cert, key string, cas []string) MTLSConfig {
	return MTLSConfig{RESTUpstreamMTLS: grpcclient.TLSClient{
		Enable:   true,
		CertFile: cert,
		KeyFile:  key,
		CAFiles:  cas,
	}}
}

// Фрагменты отказов, по которым различаются две ветви стража. Берутся из его
// собственного текста: тон отказа — часть контракта, и проба, сверяющая только
// код, не заметила бы, что оператору перестали говорить, ЧТО задавать.
const (
	restUpstreamPairComplaint   = "сертификат или ключ не заданы"
	restUpstreamAnchorComplaint = "не задан набор корней"
)

func TestRESTUpstreamCredentialGuard(t *testing.T) {
	const (
		cert = "/etc/kaname/tls/client/tls.crt"
		key  = "/etc/kaname/tls/client/tls.key"
	)
	anchors := []string{"/etc/kaname/tls/client/ca.crt"}

	for _, c := range []struct {
		name string
		cfg  MTLSConfig
		// wantPair / wantAnchor — какие ветви обязаны отказать. Утверждаются
		// ОБЕ, в том числе отрицанием: без «эта ветвь молчать обязана» проба
		// зеленела бы на стráже, отвергающем всё подряд.
		wantPair   bool
		wantAnchor bool
	}{
		{
			name: "обе половины и якорь — молчит",
			cfg:  restUpstreamOnly(cert, key, anchors),
		},
		{
			name:     "только сертификат — ключа нет",
			cfg:      restUpstreamOnly(cert, "", anchors),
			wantPair: true,
		},
		{
			name:     "только ключ — сертификата нет",
			cfg:      restUpstreamOnly("", key, anchors),
			wantPair: true,
		},
		{
			name:       "пара есть, якоря нет",
			cfg:        restUpstreamOnly(cert, key, nil),
			wantAnchor: true,
		},
		{
			// Выключенное удостоверение — ЗАКОННАЯ посадка (внешний поставщик
			// личности, фронт своему слушателю не представляется). Страж на ней
			// обязан молчать при ПУСТЫХ величинах: иначе он требовал бы
			// материала от посадки, где его не бывает.
			name: "удостоверение выключено — величин нет и отказа нет",
			cfg:  MTLSConfig{RESTUpstreamMTLS: grpcclient.TLSClient{Enable: false}},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			text := ""
			if err != nil {
				text = err.Error()
			}

			if got := strings.Contains(text, restUpstreamPairComplaint); got != c.wantPair {
				t.Errorf("отказ о ПАРЕ: получено %v, ожидалось %v; текст: %q", got, c.wantPair, text)
			}
			if got := strings.Contains(text, restUpstreamAnchorComplaint); got != c.wantAnchor {
				t.Errorf("отказ о ЯКОРЕ: получено %v, ожидалось %v; текст: %q", got, c.wantAnchor, text)
			}
			if !c.wantPair && !c.wantAnchor && err != nil {
				t.Errorf("законная посадка отвергнута: %v", err)
			}
			if (c.wantPair || c.wantAnchor) && err == nil {
				t.Error("посадка с неполным удостоверением принята — служба поднялась бы, " +
					"а отказ приходил бы арендатору на каждом запросе")
			}
		})
	}
}

// TestRESTUpstreamCredentialGuard_BothHalvesMissingIsOneComplaintNotZero —
// вырожденный случай: включено, а не задано НИЧЕГО.
//
// Стоит отдельно, потому что это единственный мир, где обе ветви обязаны
// сработать разом. Страж, склеивающий их в одну, оставил бы оператора без
// половины задания.
func TestRESTUpstreamCredentialGuard_BothHalvesMissingIsOneComplaintNotZero(t *testing.T) {
	err := restUpstreamOnly("", "", nil).Validate()
	if err == nil {
		t.Fatal("включённое и полностью незаданное удостоверение принято")
	}
	for _, want := range []string{restUpstreamPairComplaint, restUpstreamAnchorComplaint} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q — оператор задаст половину и получит тот же отказ: %v", want, err)
		}
	}
}
