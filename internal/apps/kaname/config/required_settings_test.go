// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// required_settings_test.go — доказательство того, что таблица обязательных
// величин НЕ МОЖЕТ ЛГАТЬ.
//
// # Зачем таблица вообще
//
// Документ установки для чужого оператора обязан назвать величины, без которых
// служба не пускается. Выписанный от руки перечень разошёлся бы со стражем
// молча: страж меняется коммитом в свой файл, документ — не меняется вовсе, и
// расхождение видит только тот, кто в этот день ставит службу впервые.
//
// Поэтому перечень ПОРОЖДАЕТСЯ из таблицы, а таблица доказывается ПРОГОНОМ.
// Здесь — доказательство; порождение и сверка с документом — в
// services/iam/tools/operatordocs.
//
// # Четыре утверждения, и ни одно не заменяет другого
//
//	Т1  каждая строка НАСТОЯЩАЯ  — снятая величина роняет старт, и отказ
//	                               называет именно её координату;
//	Т2  ПУТЬ ПОДАЧИ не лжёт     — полный профиль, собранный ОБЪЯВЛЕННЫМИ
//	                               путями, проходит стража целиком. Это главное
//	                               утверждение файла: у двух ключей путь через
//	                               окружение НЕ РАБОТАЕТ, и документ, назвавший
//	                               его, отправил бы оператора по кругу;
//	Т3  таблица ПОЛНАЯ          — на пустом профиле каждый отказ стража
//	                               принадлежит какой-то строке, и каждая
//	                               безусловная применимая строка отказ
//	                               производит;
//	Т4  оболочка заполнена      — пустая клетка в порождённом документе
//	                               читается оператором как «здесь ничего не нужно».
//
// Т1 без Т2 оставляет документ, верно называющий величину и неверно — способ её
// задать. Т1+Т2 без Т3 оставляют перечень, у которого каждая строка настоящая, а
// вместе они старта не покрывают.
//
// # Почему разбор вынесен в функцию, а не написан прямо в пробе
//
// Гейт обязан быть СПОСОБЕН УПАСТЬ, и доказывается это подачей ему битой
// таблицы (required_settings_injection_test.go). Разбор, обращающийся к
// `*testing.T` напрямую, инъекции не поддаётся: падение подставной таблицы
// уронило бы саму пробу способности падать. Поэтому `auditRequiredSettings`
// принимает таблицу и ВОЗВРАЩАЕТ находки, а окружение сохраняет и
// восстанавливает сам.
package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// lanesUnderTest — полосы посадки личности, на которых прогоняется таблица.
// Обе, а не одна: у каждой свой набор применимых строк, и полоса, оставшаяся
// вне прогона, унесла бы с собой доказательство своих строк.
var lanesUnderTest = []config.IdentityProvider{
	config.IdentityProviderExternal,
	config.IdentityProviderOwn,
}

// auditCensus — объём осмотренного. Печатается ВСЕГДА: без него «находок 0»
// неотличимо от «не прочитано ничего».
type auditCensus struct {
	Rows       int
	Lanes      int
	Cells      int
	Refusals   map[string]int
	Applicable map[string]int
}

func (c auditCensus) String() string {
	lanes := make([]string, 0, len(c.Refusals))
	for l := range c.Refusals {
		lanes = append(lanes, l)
	}
	sort.Strings(lanes)
	parts := make([]string, 0, len(lanes))
	for _, l := range lanes {
		parts = append(parts, fmt.Sprintf("%s: отказов стража %d, применимых строк %d",
			l, c.Refusals[l], c.Applicable[l]))
	}
	return fmt.Sprintf("строк таблицы %d · полос %d · клеток «строка × полоса» %d · %s",
		c.Rows, c.Lanes, c.Cells, strings.Join(parts, " · "))
}

// ─────────────────────────────────────────────────────────────────────────────
// ОКРУЖЕНИЕ. Разбор ставит переменные сам и возвращает окружение как было —
// иначе прогон подставной таблицы протёк бы в соседнюю пробу.

const envPrefix = "KANAME_"

func snapshotEnv() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i > 0 && strings.HasPrefix(kv[:i], envPrefix) {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func clearOwnEnv() {
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i > 0 && strings.HasPrefix(kv[:i], envPrefix) {
			_ = os.Unsetenv(kv[:i])
		}
	}
}

func restoreEnv(saved map[string]string) {
	clearOwnEnv()
	for k, v := range saved {
		_ = os.Setenv(k, v)
	}
}

// supplyProfile собирает профиль из строк таблицы, применимых к полосе, минус
// одна снятая (пустое `omit` — полный профиль), подавая каждую ОБЪЯВЛЕННЫМ ей
// путём. Возвращает загруженную конфигурацию либо ошибку сборки.
//
// Окружение здесь НЕ ВОССТАНАВЛИВАЕТСЯ: часть секретов резолвится ЛЕНИВО — из
// переменной, названной соседним ключом настройки, и читается в момент
// `Validate()`, а не `Load()`. Восстановление на выходе из сборки унесло бы
// переменную до того, как страж её прочтёт, и профиль, собранный верно,
// выглядел бы недособранным. Снимок и восстановление делает разбор целиком.
func supplyProfile(dir string, table []config.RequiredSetting, lane config.IdentityProvider, omit string) (config.Config, error) {
	clearOwnEnv()
	if err := os.Setenv("KANAME_AUTHN__MODE", "production"); err != nil {
		return config.Config{}, err
	}

	fileTree := map[string]any{}
	supplied := 0
	for _, s := range table {
		if !s.AppliesTo(lane) || s.Key == omit {
			continue
		}
		supplied++
		switch s.Supply {
		case config.SupplyEnv:
			if err := os.Setenv(s.Env, s.SampleValue(lane)); err != nil {
				return config.Config{}, err
			}
		case config.SupplyFile:
			putPath(fileTree, s.Key, s.FileValue(lane))
		default:
			return config.Config{}, fmt.Errorf("строка %s объявила неизвестный путь подачи %v", s.Key, s.Supply)
		}
	}
	if supplied == 0 && omit == "" {
		return config.Config{}, fmt.Errorf("полоса %s не несёт НИ ОДНОЙ применимой строки: обход пуст", lane)
	}

	path := ""
	if len(fileTree) > 0 {
		body, err := yaml.Marshal(fileTree)
		if err != nil {
			return config.Config{}, fmt.Errorf("файл настроек не собран: %w", err)
		}
		path = filepath.Join(dir, fmt.Sprintf("iam-%s-%s.yaml", lane, strings.NewReplacer(".", "_", "/", "_").Replace(omit)))
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return config.Config{}, fmt.Errorf("файл настроек не записан: %w", err)
		}
	}
	return config.Load(path)
}

// emptyProfile — боевой профиль, в котором объявлена ТОЛЬКО полоса. Им
// доказывается полнота таблицы.
func emptyProfile(lane config.IdentityProvider) (config.Config, error) {
	clearOwnEnv()
	if err := os.Setenv("KANAME_AUTHN__MODE", "production"); err != nil {
		return config.Config{}, err
	}
	if err := os.Setenv("KANAME_AUTHN__IDENTITY_PROVIDER", lane.String()); err != nil {
		return config.Config{}, err
	}
	return config.Load("")
}

// putPath раскладывает точечный путь ключа во вложенные карты — ту форму, в
// которой файл настроек читает випер.
func putPath(tree map[string]any, key string, value any) {
	parts := strings.Split(key, ".")
	cur := tree
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
}

func refusals(cfg config.Config) []string {
	var out []string
	for _, e := range multierr.Errors(cfg.Validate()) {
		out = append(out, e.Error())
	}
	return out
}

func mentions(list []string, needle string) bool {
	for _, s := range list {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// РАЗБОР. Возвращает находки и объём осмотренного.

func auditRequiredSettings(dir string, table []config.RequiredSetting) ([]string, auditCensus) {
	// Снимок и восстановление — на ВЕСЬ разбор: ленивые секреты читаются в
	// момент `Validate()`, поэтому переменная обязана дожить до него.
	saved := snapshotEnv()
	defer restoreEnv(saved)

	var findings []string
	census := auditCensus{
		Rows:       len(table),
		Lanes:      len(lanesUnderTest),
		Refusals:   map[string]int{},
		Applicable: map[string]int{},
	}

	if len(table) == 0 {
		return []string{"таблица обязательных величин пуста — порождённый перечень был бы пуст молча"}, census
	}

	// Т4 — оболочка строки заполнена.
	seenKey := map[string]bool{}
	for _, s := range table {
		switch {
		case s.Key == "":
			findings = append(findings, "строка без координаты ключа: порождённая таблица получила бы пустую клетку")
			continue
		case seenKey[s.Key]:
			findings = append(findings, s.Key+": ключ объявлен дважды — два места об одном предмете разойдутся молча")
		}
		seenKey[s.Key] = true
		if strings.TrimSpace(s.Why) == "" {
			findings = append(findings, s.Key+": не сказано, ПОЧЕМУ без величины не пускаемся — оператор прочтёт требование как каприз")
		}
		if strings.TrimSpace(s.Refusal) == "" {
			findings = append(findings, s.Key+": не названа подстрока отказа — доказать строку прогоном нечем")
		}
		if strings.TrimSpace(s.SampleValue(config.IdentityProviderExternal)) == "" {
			findings = append(findings, s.Key+": нет годного значения — подать величину прогоном нечем")
		}
		if s.Supply == config.SupplyEnv && strings.TrimSpace(s.Env) == "" {
			findings = append(findings, s.Key+": путь подачи — окружение, а имя переменной не названо")
		}
	}

	for _, lane := range lanesUnderTest {
		// Т2 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ полосы: полный профиль, собранный
		// объявленными путями, проходит стража целиком. Без него отрицания ниже
		// зеленели бы на профиле, сломанном чем угодно.
		full, err := supplyProfile(dir, table, lane, "")
		if err != nil {
			findings = append(findings, fmt.Sprintf("полоса %s: профиль не собран: %v", lane, err))
			continue
		}
		if got := refusals(full); len(got) != 0 {
			findings = append(findings, fmt.Sprintf(
				"полоса %s: полный профиль, собранный ОБЪЯВЛЕННЫМИ путями подачи, отвергнут стражем — "+
					"значит таблица не полна либо путь подачи какой-то строки объявлен неверно; остаточные отказы:\n    %s",
				lane, strings.Join(got, "\n    ")))
		}

		// Т1 — каждая строка настоящая.
		for _, s := range table {
			if !s.AppliesTo(lane) {
				continue
			}
			census.Cells++
			census.Applicable[lane.String()]++

			cfg, err := supplyProfile(dir, table, lane, s.Key)
			if err != nil {
				findings = append(findings, fmt.Sprintf("полоса %s, снята %s: профиль не собран: %v", lane, s.Key, err))
				continue
			}
			if !mentions(refusals(cfg), s.Refusal) {
				findings = append(findings, fmt.Sprintf(
					"полоса %s: величина %s снята, а страж на неё не отказал (искали подстроку %q) — "+
						"порождённый документ потребовал бы значение, без которого служба поднимается",
					lane, s.Key, s.Refusal))
			}
		}

		// Т3 — таблица полная.
		empty, err := emptyProfile(lane)
		if err != nil {
			findings = append(findings, fmt.Sprintf("полоса %s: пустой профиль не собран: %v", lane, err))
			continue
		}
		got := refusals(empty)
		census.Refusals[lane.String()] = len(got)
		if len(got) == 0 {
			findings = append(findings, fmt.Sprintf(
				"полоса %s: пустой боевой профиль прошёл стража — утверждение о полноте было бы вакуумным", lane))
			continue
		}
		for _, r := range got {
			owned := false
			for _, s := range table {
				if s.AppliesTo(lane) && strings.Contains(r, s.Refusal) {
					owned = true
					break
				}
			}
			if !owned {
				findings = append(findings, fmt.Sprintf(
					"полоса %s: страж отказал в старте, и НИ ОДНА строка таблицы этого отказа не объясняет:\n    %s\n"+
						"    значит есть обязательная величина, которой порождённый документ не называет", lane, r))
			}
		}
		for _, s := range table {
			// Строка посадки личности на этом прогоне уже подана — полосу
			// надо выбрать, чтобы у полосы были свои строки.
			if !s.AppliesTo(lane) || s.Key == config.IdentityProviderSetting {
				continue
			}
			// УСЛОВНАЯ строка на пустом профиле отказа не производит by
			// construction: её условие (заданная соседняя величина) не
			// выполнено. Требовать от неё отказа здесь значило бы требовать от
			// стража срабатывания без собственного предмета.
			if s.Conditional {
				continue
			}
			if !mentions(got, s.Refusal) {
				findings = append(findings, fmt.Sprintf(
					"полоса %s: строка %s объявлена безусловно обязательной, а пустой профиль на неё не отказал — "+
						"документ потребовал бы величину, которой страж не требует", lane, s.Key))
			}
		}
	}

	return findings, census
}

// ─────────────────────────────────────────────────────────────────────────────

func TestRequiredSettings_TableCannotLie(t *testing.T) {
	findings, census := auditRequiredSettings(t.TempDir(), config.RequiredSettings)
	for _, f := range findings {
		t.Error(f)
	}
	if census.Cells == 0 {
		t.Fatal("обход пуст: не проверено ни одной клетки «строка × полоса» — гейт судил бы о непрочитанном")
	}
	t.Logf("перепись: %s · находок %d", census, len(findings))
}
