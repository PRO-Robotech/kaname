// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// posture_test.go — посадка kacho-iam судится ЦЕНТРАЛЬНЫМ дескриптором
// (задача продукта #1406).
//
// Пробы стоят здесь, а не в пакете настройки, ровно потому, что предмет
// переехал: ось шифрования до собственной базы решает теперь `describePosture`,
// а `config.Config.Validate` о ней не утверждает ничего. Проба, оставленная у
// прежнего места, была бы утверждением про то, чего там больше нет.

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// postureCfg — настройка, у которой ВСЕ прочие оси посадки выполнены, чтобы
// единственной переменной пробы осталась названная ею.
func postureCfg(mode config.Mode, sslMode string) config.Config {
	var cfg config.Config
	cfg.AuthN.Mode = mode
	cfg.AuthN.TrustedForwarderSANs = []string{"spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"}
	cfg.Repository.Postgres.URL = "postgres://u:p@db:5432/kacho_iam"
	cfg.Repository.Postgres.SSLMode = sslMode
	cfg.Retention = config.RetentionConfig{Interval: 5 * time.Minute, Batch: 1000, MaxBatchesPerPass: 20}
	return cfg
}

func describeFor(t *testing.T, cfg config.Config) error {
	t.Helper()
	_, err := describePosture(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return err
}

// TestPosture_ProductionRefusesPlaintextDBLink — боевая посадка с открытым
// каналом до собственной базы не поднимается. Через эту связь идут записи
// пользователей и служебных учёток, строки отзыва сессий и токенов и только что
// выданный секрет ключа служебной учётки, кратко лежащий в результате операции
// до вымарывания.
func TestPosture_ProductionRefusesPlaintextDBLink(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeProduction, config.ModeProductionStrict} {
		t.Run(mode.String(), func(t *testing.T) {
			err := describeFor(t, postureCfg(mode, "disable"))
			if err == nil {
				t.Fatal("боевая посадка принята с sslmode=disable: данные арендатора шли бы " +
					"к базе открытым каналом, и соседу по сети достаточно слушать")
			}
			if !strings.Contains(err.Error(), "DBSSLMode") {
				t.Fatalf("отказ обязан назвать ось, которую править, получено: %v", err)
			}
		})
	}
}

// TestPosture_ProductionRefusesUnsetDBLink — незаданный режим деривится в
// `disable` строкой, уходящей в пул, и отвергается так же. Отдельная проба, а не
// подслучай: «не выбрали» и «выбрали открытый» — разные действия оператора, и
// обе обязаны кончаться отказом.
func TestPosture_ProductionRefusesUnsetDBLink(t *testing.T) {
	err := describeFor(t, postureCfg(config.ModeProduction, ""))
	if err == nil {
		t.Fatal("боевая посадка принята с незаданным sslmode — строка, уходящая в пул, " +
			"деривит его в disable, то есть в открытый канал")
	}
	if !strings.Contains(err.Error(), "DBSSLMode") {
		t.Fatalf("отказ обязан назвать ось, которую править, получено: %v", err)
	}
}

// TestPosture_ProductionAcceptsEverySecureDBLink — положительный контроль. Без
// него отрицание выше зеленело бы и на дескрипторе, отвергающем всё подряд.
func TestPosture_ProductionAcceptsEverySecureDBLink(t *testing.T) {
	for _, m := range []string{"require", "verify-ca", "verify-full"} {
		if err := describeFor(t, postureCfg(config.ModeProduction, m)); err != nil {
			t.Fatalf("боевая посадка с sslmode=%q обязана приниматься, получен отказ: %v", m, err)
		}
	}
}

// TestPosture_SSLModeIsReadFromTheStringThatReachesThePool — режим, заданный
// ПРЯМО В URL, принимается: судится строка, уходящая в пул, а не поле настройки
// рядом с ней.
//
// Именно этим переезд оси исправил её предмет: снятая копия читала поле, и такой
// стенд она отвергала при исправной посадке.
func TestPosture_SSLModeIsReadFromTheStringThatReachesThePool(t *testing.T) {
	cfg := postureCfg(config.ModeProduction, "")
	cfg.Repository.Postgres.URL = "postgres://u:p@db:5432/kacho_iam?sslmode=verify-ca"
	if err := describeFor(t, cfg); err != nil {
		t.Fatalf("режим, заданный в самом URL, обязан приниматься — в пул уходит именно он; получено: %v", err)
	}
}

// TestPosture_DevKeepsThePlaintextDBLink — вне боевого режима открытый канал до
// базы остаётся законным. Отрицательный контроль к предыдущим: без него они
// зеленели бы и на дескрипторе, отвергающем `disable` в любом режиме, — а это
// сломало бы каждую внутрипроцессную фикстуру.
func TestPosture_DevKeepsThePlaintextDBLink(t *testing.T) {
	if err := describeFor(t, postureCfg(config.ModeDev, "disable")); err != nil {
		t.Fatalf("вне боевого режима открытый канал до базы законен, получен отказ: %v", err)
	}
}

// TestPosture_RefusesAnUnnarrowedForwarderCircle — круг отправителей переданной
// личности судится тем же дескриптором. Проба не дублирует ту, что стоит у
// настройки: там она утверждает про раннюю проверку в `main`, здесь — про то,
// что ЦЕНТРАЛЬНЫЙ источник ту же ось судит и один отказ не подменяет другой.
func TestPosture_RefusesAnUnnarrowedForwarderCircle(t *testing.T) {
	cfg := postureCfg(config.ModeProduction, "require")
	cfg.AuthN.TrustedForwarderSANs = nil
	err := describeFor(t, cfg)
	if err == nil {
		t.Fatal("боевая посадка принята с несужённым кругом отправителей: любой пир с " +
			"проверенным сертификатом передавал бы личность конечного пользователя")
	}
	if !strings.Contains(err.Error(), "Forwarders") {
		t.Fatalf("отказ обязан назвать ось, которую править, получено: %v", err)
	}
}

// TestPosture_RefusesAnUnknownMode — режим, которого нет в словаре, до
// дескриптора не доходит: разбор отказывает раньше, и отказ называет ручку.
//
// Значение вне перечисления берётся не из воздуха: `config.Mode` — целочисленный
// перечислитель, разбираемый из настройки, и величина за его границей приходит
// из профиля, который написал что-то своё.
func TestPosture_RefusesAnUnknownMode(t *testing.T) {
	cfg := postureCfg(config.Mode(42), "require")
	err := describeFor(t, cfg)
	if err == nil {
		t.Fatal("посадка принята с режимом вне словаря — молчаливое умолчание здесь " +
			"есть решение о доступе, принятое никем")
	}
	if !strings.Contains(err.Error(), "authn.mode") {
		t.Fatalf("отказ обязан назвать ручку, получено: %v", err)
	}
}

// TestPosture_CarriesNoCarrierWiring — контур входящего пути iam носитель не
// поднимает, и проводку носителя корень не приносит. Проба утверждает ИСХОД
// (дескриптор принят и объявил собственный контур), а не то, что автор написал в
// комментарии.
func TestPosture_CarriesNoCarrierWiring(t *testing.T) {
	desc, err := describePosture(postureCfg(config.ModeProduction, "require"),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("посадка обязана приниматься: %v", err)
	}
	if desc.OwnContour() == "" {
		t.Fatal("контур входящего пути iam собран в его композиционном корне, а дескриптор " +
			"объявил обратное: носитель тогда поднял бы контур по проводке, которой нет")
	}
}
