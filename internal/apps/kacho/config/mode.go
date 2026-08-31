// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package config — configuration for kacho-iam.
//
// YAML + viper. Defaults are kept in defaults.go (not in struct-tags).
// ENV-binding lives in load.go via `viper.SetEnvPrefix("KACHO_IAM")` +
// delimiter `__` for hierarchy (`KACHO_IAM_REPOSITORY__POSTGRES__URL` →
// `repository.postgres.url`).
//
// Mode: ENUM Mode{ModeDev, ModeProduction, ModeProductionStrict} — overall
// service mode (anonymous-allowed / fail-closed / fail-closed+strict-TLS).
// The same ENUM governs the mandatory JWT (Kratos/Hydra) on the
// public-listener once AuthN core is wired.
package config

import (
	"encoding/json"
	"fmt"

	"github.com/PRO-Robotech/kacho/pkg/servicecontract"
)

// Mode — overall service mode.
//
//	ModeDev              — anonymous-mode permitted (interceptor lets callers
//	                       through without AuthN-headers as admin); insecure
//	                       dev-defaults (TLS off, sslmode=disable) are only
//	                       logged.
//	ModeProduction       — fail-closed: every request must carry a non-empty
//	                       principal-ctx. Anonymous → PermissionDenied.
//	ModeProductionStrict — production + additionally validates extapi.*.tls.*
//	                       and repository.postgres.ssl-mode
//	                       (require|verify-ca|verify-full).
type Mode int

// ENUM values. iota order is stable; don't change without a values.yaml
// migration.
const (
	ModeDev Mode = iota
	ModeProduction
	ModeProductionStrict
)

// String — каноническое имя для журнала и текстов отказа. Берётся у ДОМА
// словаря, а не пишется здесь: имя и разбор — две стороны одного соответствия, и
// объявленные порознь они разошлись бы молча.
func (m Mode) String() string {
	host, known := m.host()
	if !known {
		// Значение вне перечня сюда не приходит: разбор его отвергает. Ветка
		// остаётся ради ЧИТАЕМОСТИ отказа, если оно всё же появится — иначе
		// невозможное значение напечаталось бы именем законной посадки, и
		// разбирающий пошёл бы искать не там.
		return fmt.Sprintf("mode(%d)", int(m))
	}
	return host.String()
}

// host переводит режим сервиса в общий словарь посадки. Второе значение — знал
// ли перевод, что переводит: «не знаю» и «dev» обязаны быть различимы, иначе
// невозможное значение молча читалось бы как самая слабая посадка.
func (m Mode) host() (servicecontract.Mode, bool) {
	switch m {
	case ModeDev:
		return servicecontract.ModeDev, true
	case ModeProduction:
		return servicecontract.ModeProduction, true
	case ModeProductionStrict:
		return servicecontract.ModeProductionStrict, true
	default:
		return 0, false
	}
}

// IsProduction returns true for any production variant.
func (m Mode) IsProduction() bool {
	return m == ModeProduction || m == ModeProductionStrict
}

// parseMode — pointwise inverse of String(); used by the custom
// mapstructure hook and the YAML/ENV loader.
//
// Словарь допустимых написаний — НЕ свой: он объявлен в дереве один раз
// (`servicecontract.Modes`), и отказ перечисляет ТОТ ЖЕ набор, что у остальных
// шести стражей старта. Свой словарь здесь был, и он был одним из пяти; копии не
// собираются вместе и друг друга не читают, поэтому расхождение приходило молча —
// один из пяти расходился с остальными В ОБЕ СТОРОНЫ (задача продукта #1656).
//
// Неизвестное значение спарено с БОЕВЫМ режимом, а не с dev: оба вызывающих
// (хук mapstructure и UnmarshalJSON) на ошибке прерываются, но вызывающий,
// игнорирующий ошибку, обязан получить fail-closed, а не анонимный полный доступ.
func parseMode(s string) (Mode, error) {
	switch mode, err := servicecontract.ParseMode(s); {
	case err != nil:
		return ModeProduction, err
	case mode == servicecontract.ModeDev:
		return ModeDev, nil
	case mode == servicecontract.ModeProductionStrict:
		return ModeProductionStrict, nil
	default:
		return ModeProduction, nil
	}
}

// MarshalJSON / UnmarshalJSON — convenient serialisation.
func (m Mode) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }

func (m *Mode) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := parseMode(s)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}
