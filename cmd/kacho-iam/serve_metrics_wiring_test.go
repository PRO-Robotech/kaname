// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// TestMetricsListener_ConfiguredSeparatePort — the composition root must serve
// /metrics on a SEPARATE cluster-internal port (default :9095), never the
// public tenant gRPC surface (exposing the registry there would leak internal
// cardinality — security.md). Behavioural check against the loaded config.
func TestMetricsListener_ConfiguredSeparatePort(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	metricsAddr := cfg.APIServer.MetricsListenAddress()
	if metricsAddr == "" {
		t.Fatal("metrics listener disabled by default — observability gap")
	}
	if metricsAddr == cfg.APIServer.ListenAddress() {
		t.Errorf("metrics addr %q == public gRPC addr — must be a separate port", metricsAddr)
	}
	if metricsAddr == cfg.APIServer.InternalListenAddress() {
		t.Errorf("metrics addr %q == internal gRPC addr — must be a separate port", metricsAddr)
	}
}

// TestServeWiresMetricsInterceptorAndListener — страж композиционного корня.
// serve.go обязан (1) завести реестр, (2) провязать измеритель задержки на ОБА
// слушателя РАЗНЫМИ полосами и (3) поднять поверхность /metrics.
//
// # Что здесь изменилось и почему это не ослабление
//
// Прежде страж искал `metricsReg.UnaryServerInterceptor()` дважды. Своей пары
// серий у iam больше нет: её предмет тот же, что у платформенного измерителя
// `pkg/grpcsrv.ServerLatency`, и два места об одном предмете уже разошлись по
// трём осям (исход смешан с успехом, полоса слушателя не различалась, сетка
// корзин взята по умолчанию). Искать в исходнике имя снятого метода значило бы
// требовать дефекта.
//
// Утверждение стало СТРОЖЕ, а не слабее: прежде обе строки были одинаковы, и
// провязка одного и того же слушателя дважды прошла бы. Теперь каждая полоса
// названа поимённо, поэтому «оба слушателя» проверяется буквально.
//
// RED-демонстрация: снять любую из двух строк полосы — страж краснеет до мёржа.
func TestServeWiresMetricsInterceptorAndListener(t *testing.T) {
	src := readFileT(t, "serve.go")

	for _, want := range []string{
		"metrics.NewRegistry()",
		// Измеритель заводится СКВОЗЬ окно регистрации того же реестра, который
		// скребут: собранный над чужим реестром, он считал бы в пустоту, и отказ
		// старта этого не увидел бы.
		"grpcsrv.NewServerLatency(metricsReg.Registerer())",
		"latency.UnaryServerInterceptor(grpcsrv.ListenerPublic)",
		"latency.UnaryServerInterceptor(grpcsrv.ListenerInternal)",
		"cfg.APIServer.MetricsListenAddress()",
		`metricsMux.Handle("/metrics", metricsReg.Handler())`,
		// Подъём и гашение слушателя ЗДЕСЬ БОЛЬШЕ НЕ ИЩУТСЯ, и это не ослабление:
		// они переехали в профиль не-gRPC поверхности, а искать в исходнике имя
		// снятого поля значит требовать дефекта. Что поверхность действительно
		// поднимается и действительно гасится, утверждают ДВЕ пробы на поведении:
		// `TestIAMSurfacesServeAndReleaseTheirPorts` (в этом же пакете) и
		// `TestSurfaceReleasesItsPortBeforeReturning` (pkg/servicehost). Обе
		// проверяют исход на проводе, а не наличие строки.
		"servicehost.ServeSurface(",
		// Состояние пулов соединений. Без этих двух строк коллектор существует,
		// собран и не зарегистрирован ни у кого — то есть на /metrics его нет, а
		// в дереве он выглядит сделанной работой. Пулов у kacho-iam два, и оба
		// обязаны быть провязаны: одна строка означала бы, что второй пул
		// ненаблюдаем при полностью исправном коллекторе.
		`metricsReg.RegisterPoolStats("primary", pool)`,
		`metricsReg.RegisterPoolStats("replica", slavePool)`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: missing metrics wiring %q", want)
		}
	}

	// Измеритель обязан стоять на ОБОИХ серверах и РАЗНЫМИ полосами: один и тот
	// же метод служится обоими слушателями, и одна полоса на двоих слила бы два
	// ряда в один — среднее двух разных величин.
	if got := strings.Count(src, "latency.UnaryServerInterceptor("); got != 2 {
		t.Errorf("измеритель задержки провязан %d раз, ожидалось 2 (публичный + внутренний)", got)
	}
	// Прежняя пара серий не имеет права вернуться: две серии об одном предмете
	// расходятся, и оставленная про запас читалась бы панелями как живая.
	if strings.Contains(src, "metricsReg.UnaryServerInterceptor()") {
		t.Error("собственный интерсептор метрик iam вернулся в композиционный корень: " +
			"его предмет тот же, что у платформенного измерителя, и две серии об одном " +
			"предмете уже разошлись однажды")
	}
	// Подписки обоих слушателей тоже наблюдаются: iam служит стрим отражения, и
	// оборванная подписка иначе не видна нигде.
	if got := strings.Count(src, "latency.StreamServerInterceptor("); got != 2 {
		t.Errorf("измеритель подписок провязан %d раз, ожидалось 2 (публичный + внутренний)", got)
	}
}
