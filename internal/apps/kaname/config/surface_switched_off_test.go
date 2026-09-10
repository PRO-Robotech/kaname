// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// surface_switched_off_test.go — ПУСТОЙ АДРЕС, ОБЪЯВЛЕННЫЙ ПРОФИЛЕМ, ГАСИТ
// ПОВЕРХНОСТЬ.
//
// # Предмет
//
// «Выключено» у поверхности выражается пустым адресом — так это читает и сам
// процесс, и каждый его страж («пустой адрес — слушателя нет, судить нечего»).
// У четырёх поверхностей адрес приходит НЕПУСТЫМ умолчанием, поэтому они
// поднимаются всегда, и выключить их можно ровно одним способом: объявив адрес
// пустым (задача #2477).
//
// Проба судит ТУ ЖЕ функцию, которую зовёт композиционный корень
// (`config.Load`), а не свою сборку значений: своя разошлась бы с настоящим
// загрузчиком молча — и разошлась бы именно на порядке умолчаний, где весь
// предмет и живёт.
//
// # Почему проверяется ФАЙЛ настроек, а не переменная окружения
//
// Оба пути объявлены, и работает из них один. `AutomaticEnv` без
// `AllowEmptyEnv` читает пустую переменную как НЕЗАДАННУЮ и возвращает то же
// умолчание — то есть переменной поверхность не гасится ни при каком входе.
// Путь, которым оператор располагает, — файл настроек, и его эмитит чарт
// (`hasKey`-ветвь в configmap.yaml). Эта проба утверждает про него.
//
// Вторая половина — что переменной погасить НЕЛЬЗЯ — утверждается здесь же
// отдельным случаем: без неё «файлом гасится» читалось бы как «гасится любым
// путём», и следующий оператор пошёл бы переменной.
//
// # Положительный контроль обязателен
//
// Отрицание «пустое значение даёт пустой адрес» зеленело бы на загрузчике,
// который этот ключ вообще не читает. Поэтому тот же ключ проверяется и
// НЕПУСТЫМ: он обязан доехать своим значением.
package config

import (
	"os"
	"path/filepath"
	"testing"
)

// surfaceAddrCase — одна поверхность, поднимаемая непустым умолчанием.
type surfaceAddrCase struct {
	name string
	// yaml — тело настроек, объявляющее адрес этой поверхности значением %s.
	yaml func(value string) string
	// addr — как процесс читает адрес поверхности из собранной настройки.
	addr func(Config) string
}

func surfaceAddrCases() []surfaceAddrCase {
	return []surfaceAddrCase{
		{
			name: "api-server.metrics-endpoint",
			yaml: func(v string) string { return "api-server:\n  metrics-endpoint: \"" + v + "\"\n" },
			addr: func(c Config) string { return c.APIServer.MetricsListenAddress() },
		},
		{
			name: "api-server.jwks-proxy.endpoint",
			yaml: func(v string) string {
				return "api-server:\n  jwks-proxy:\n    endpoint: \"" + v + "\"\n"
			},
			addr: func(c Config) string { return c.APIServer.JWKSProxy.ListenAddress() },
		},
		{
			name: "api-server.registry-token.endpoint",
			yaml: func(v string) string {
				return "api-server:\n  registry-token:\n    endpoint: \"" + v + "\"\n"
			},
			addr: func(c Config) string { return c.APIServer.RegistryToken.ListenAddress() },
		},
		{
			name: "authn.hooks-http-endpoint",
			yaml: func(v string) string { return "authn:\n  hooks-http-endpoint: \"" + v + "\"\n" },
			addr: func(c Config) string { return c.AuthN.HooksHTTPListenAddress() },
		},
	}
}

func loadFromBody(t *testing.T, body string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("тело настроек не записано: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("настройки не собираются: %v", err)
	}
	return cfg
}

func TestDeclaredEmptyAddressSwitchesTheSurfaceOff(t *testing.T) {
	cases := surfaceAddrCases()
	if len(cases) == 0 {
		t.Fatal("обход пуст: поверхностей к проверке 0 — вердикт беспредметен")
	}
	const moved = "tcp://0.0.0.0:19999"

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// ПРЕДПОСЫЛКА: умолчание этой поверхности непусто — иначе гасить
			// нечего и проба была бы вакуумной.
			if got := c.addr(loadFromBody(t, "logger:\n  level: INFO\n")); got == "" {
				t.Fatalf("умолчание поверхности пусто — предмет пробы отсутствует")
			}

			// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: объявленное значение доезжает.
			if got := c.addr(loadFromBody(t, c.yaml(moved))); got != "0.0.0.0:19999" {
				t.Fatalf("объявленный адрес не доехал: %q", got)
			}

			// ОТРИЦАНИЕ: объявленное пустым гасит поверхность.
			if got := c.addr(loadFromBody(t, c.yaml(""))); got != "" {
				t.Fatalf("адрес объявлен ПУСТЫМ, а поверхность поднимается на %q: "+
					"«выключено» здесь означает «как было»", got)
			}
		})
	}
}

// TestEmptyEnvironmentVariableDoesNotSwitchASurfaceOff — вторая половина, и она
// про ГРАНИЦУ: переменной окружения поверхность НЕ гасится.
//
// Без этого утверждения «файлом гасится» читалось бы как «гасится любым путём»,
// и следующий оператор пошёл бы переменной, получив молчаливое умолчание.
// Свойство держится не нами: `AutomaticEnv` без `AllowEmptyEnv` читает пустую
// переменную как незаданную. Проба утверждает наблюдаемое, чтобы смена этого
// поведения была замечена здесь, а не на чужом стенде.
func TestEmptyEnvironmentVariableDoesNotSwitchASurfaceOff(t *testing.T) {
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: непустая переменная поверхность ДВИГАЕТ — значит
	// ключ переменной читается, и молчание ниже не от того, что имя не то.
	t.Setenv("KANAME_API_SERVER__METRICS_ENDPOINT", "tcp://0.0.0.0:19999")
	if got := loadFromBody(t, "logger:\n  level: INFO\n").APIServer.MetricsListenAddress(); got != "0.0.0.0:19999" {
		t.Fatalf("непустая переменная не подвинула поверхность: %q — предпосылка пробы неверна", got)
	}

	t.Setenv("KANAME_API_SERVER__METRICS_ENDPOINT", "")
	got := loadFromBody(t, "logger:\n  level: INFO\n").APIServer.MetricsListenAddress()
	if got == "" {
		t.Fatal("пустая переменная погасила поверхность: граница изменилась — " +
			"чарт вправе перестать эмитить ключ файлом, и это надо решить, а не обнаружить")
	}
	t.Logf("граница подтверждена: пустая переменная оставляет умолчание %q — "+
		"гасит поверхность ТОЛЬКО объявление в файле настроек", got)
}
