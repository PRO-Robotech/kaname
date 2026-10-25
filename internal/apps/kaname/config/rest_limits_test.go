// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

// Пробы потолков публичного REST-фронта (kaname#990): умолчание безопасно,
// снятие потолка в боевой посадке не стартует, вне боевой — допустимо.

func i64(v int64) *int64 { return &v }
func iptr(v int) *int    { return &v }

// Молчание посадки — безопасные умолчания, а не «без потолка»: загрузчик
// отдаёт их по ТОЙ ЖЕ функции, что композиционный корень.
func TestRESTLimits_SilentProfileYieldsSafeDefaults(t *testing.T) {
	cfg := loadFromBody(t, "logger:\n  level: INFO\n")
	got := cfg.APIServer.RESTLimits.Effective()
	if got.MaxBodyBytes != DefaultRESTMaxBodyBytes || got.MaxInFlight != DefaultRESTMaxInFlight {
		t.Fatalf("умолчания потолков = %+v, ожидались тело %d байт и %d одновременных",
			got, DefaultRESTMaxBodyBytes, DefaultRESTMaxInFlight)
	}
	if got.MaxBodyBytes <= 0 || got.MaxInFlight <= 0 {
		t.Fatalf("умолчание обязано быть потолком, а не его снятием: %+v", got)
	}
}

// Законный близнец загрузки: объявленные величины доезжают своим значением.
func TestRESTLimits_DeclaredValuesReachTheField(t *testing.T) {
	cfg := loadFromBody(t, "api-server:\n  rest-limits:\n    max-body-bytes: 65536\n    max-in-flight: 7\n")
	got := cfg.APIServer.RESTLimits.Effective()
	if got.MaxBodyBytes != 65536 || got.MaxInFlight != 7 {
		t.Fatalf("объявленные величины не доехали: %+v", got)
	}
}

// Переменная окружения доезжает до поля: ручка без читателя — обман оператора.
func TestRESTLimits_EnvReachesTheField(t *testing.T) {
	t.Setenv("KANAME_API_SERVER__REST_LIMITS__MAX_BODY_BYTES", "4096")
	t.Setenv("KANAME_API_SERVER__REST_LIMITS__MAX_IN_FLIGHT", "3")
	cfg := loadFromBody(t, "logger:\n  level: INFO\n")
	got := cfg.APIServer.RESTLimits.Effective()
	if got.MaxBodyBytes != 4096 || got.MaxInFlight != 3 {
		t.Fatalf("переменные окружения не доехали: %+v", got)
	}
}

// Боевая посадка: снятие любого из двух потолков — отказ старта с именем ключа
// и переменной.
func TestRESTLimits_ProductionRefusesSwitchingACeilingOff(t *testing.T) {
	cases := []struct {
		name string
		cfg  RESTLimitsConfig
		key  string
		env  string
	}{
		{"тело", RESTLimitsConfig{MaxBodyBytes: i64(0)},
			"api-server.rest-limits.max-body-bytes", "KANAME_API_SERVER__REST_LIMITS__MAX_BODY_BYTES"},
		{"одновременность", RESTLimitsConfig{MaxInFlight: iptr(0)},
			"api-server.rest-limits.max-in-flight", "KANAME_API_SERVER__REST_LIMITS__MAX_IN_FLIGHT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate(true)
			if err == nil {
				t.Fatal("боевая посадка со снятым потолком стартовала")
			}
			for _, want := range []string{c.key, c.env, "refusing to start"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("отказ не называет %q: %v", want, err)
				}
			}
			if err := c.cfg.Validate(false); err != nil {
				t.Errorf("вне боевой посадки снятие потолка допустимо, а отказ: %v", err)
			}
		})
	}
}

// Отрицательная величина — отказ в ЛЮБОЙ посадке: она не означает «без
// потолка» и похожа на опечатку.
func TestRESTLimits_NegativeIsRefusedInEveryMode(t *testing.T) {
	for _, prod := range []bool{true, false} {
		if err := (RESTLimitsConfig{MaxBodyBytes: i64(-1)}).Validate(prod); err == nil {
			t.Errorf("production=%v: отрицательный потолок тела принят", prod)
		}
		if err := (RESTLimitsConfig{MaxInFlight: iptr(-1)}).Validate(prod); err == nil {
			t.Errorf("production=%v: отрицательный потолок одновременности принят", prod)
		}
	}
}

// Законный близнец стража: боевая посадка с положительными величинами и с
// умолчаниями стартует.
func TestRESTLimits_ProductionAcceptsPositiveAndDefaults(t *testing.T) {
	if err := (RESTLimitsConfig{MaxBodyBytes: i64(1), MaxInFlight: iptr(1)}).Validate(true); err != nil {
		t.Fatalf("положительные потолки отвергнуты: %v", err)
	}
	if err := (RESTLimitsConfig{}).Validate(true); err != nil {
		t.Fatalf("умолчания отвергнуты: %v", err)
	}
}

// Страж провязан в общий Validate: снятый потолок в боевой посадке роняет
// старт процесса, а не только метод.
func TestRESTLimits_GuardIsWiredIntoConfigValidate(t *testing.T) {
	var c Config
	c.AuthN.Mode = ModeProduction
	c.APIServer.RESTLimits = RESTLimitsConfig{MaxInFlight: iptr(0)}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "api-server.rest-limits.max-in-flight") {
		t.Fatalf("общий страж не назвал снятый потолок: %v", err)
	}
}
