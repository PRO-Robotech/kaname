// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_lane_memory_ceiling_test.go — ПОД `own` СТРАЖ ПОЛОСЫ ВХОДА СВЕРЯЕТ СВОЙ
// БЮДЖЕТ ПАМЯТИ С ПРЕДЕЛОМ КОНТЕЙНЕРА; ЧАРТ ОБЯЗАН УМЕТЬ ЭТОТ ПРЕДЕЛ ОБЪЯВИТЬ,
// А ПОСТАВЛЯЕМЫЙ ПРОФИЛЬ — ОБЪЯВИТЬ ЕГО ПО АРИФМЕТИКЕ СТРАЖА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (задача kaname#21, живой старт посадки `own`)
//
// Полоса входа паролем читает предел памяти У СРЕДЫ (cgroup контейнера), а не у
// настройки, и отказывает в старте, когда предела нет: «ёмкость × память на
// проверку + резерв сверять не с чем; задайте предел памяти контейнеру»
// (`config.LoginLaneConfig.ValidateMemoryBudget`, ID-PW-1 PWV-15.8). Величину
// оператор подставить в обход среды не может — в том и замысел.
//
// Замер, из которого проба выведена (2026-09-17, kind, чарт с профиля
// `values.prod.yaml` и накладкой `authn.identityProvider: own`): контейнер
// вышел с этим отказом на первом же старте. Шаблон развёртывания не рендерил
// `resources` вовсе — ни ключом профиля, ни умолчанием, — то есть посадка `own`
// была неподнимаема ПОСТАВЛЯЕМЫМ ЧАРТОМ by construction: любой профиль
// рендерился и не стартовал ни при каком входе. Класс — «возможность объявлена и
// неисполнима» (`api-conventions.md` §«Неисполнимая возможность»): страж
// требует того, чего чарт не умеет выразить.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ ПОЛОВИНЫ, И ОБЕ СУДЯТСЯ РЕНДЕРОМ
//
//	Р1  контейнер СЛУЖБЫ в рендере поставляемой цепочки несёт
//	    `resources.limits.memory`, и величина читается количеством Kubernetes.
//	    Судится контейнер по имени, а не «первый попавшийся»: у пода два
//	    контейнера, и предел на контейнере наката стражу службы не виден;
//	Р2  предел, объявленный профилем, ПРИНИМАЕТ САМ СТРАЖ: та же функция, что
//	    исполняется на старте, зовётся с величинами полосы из отрендеренной
//	    карты настроек и с пределом из отрендеренного развёртывания. Своя копия
//	    арифметики здесь не заводится намеренно — она разошлась бы со стражем
//	    молча, на первой же смене потолка формата записи пароля.
//
// Р2 рендерится с накладкой `own` (`ownPostureOverlay`: посадка, включённый
// токен-эндпоинт и его величины — без эндпоинта чарт `own` не собирает, задача
// #337): судится тот вход, который получит установка, переведённая на `own`
// поверх боевого профиля.
// Оба вердикта берутся с РЕНДЕРА, а не с текста профиля: ключ, стоящий под
// условием, в тексте есть, а в рендере его может не быть.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ПРОБА НЕ УТВЕРЖДАЕТ
//
// Она не утверждает, что предел ДОСТАТОЧЕН для процесса под нагрузкой: это
// свойство прогона, и его судит замер. Она утверждает, что страж старта примет
// этот вход, — то есть что профиль и страж говорят об одном числе.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// memoryLimitOfServiceContainer — предел памяти контейнера службы из рендера.
//
// declared=false — предел не объявлен вовсе; raw печатается переписью и идёт в
// отказ: оператор обязан увидеть, ЧТО именно прочитано, а не только вердикт.
func memoryLimitOfServiceContainer(t *testing.T, rendered string) (bytes uint64, declared bool, raw string) {
	t.Helper()
	var deployments int
	for _, doc := range strings.Split(rendered, "\n---") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var obj map[string]any
		if yaml.Unmarshal([]byte(doc), &obj) != nil {
			continue
		}
		if kind, _ := obj["kind"].(string); kind != "Deployment" {
			continue
		}
		deployments++
		meta, _ := obj["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		spec, _ := obj["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		ps, _ := tmpl["spec"].(map[string]any)
		list, _ := ps["containers"].([]any)
		for _, c := range list {
			cm, _ := c.(map[string]any)
			cname, _ := cm["name"].(string)
			// Контейнер СЛУЖБЫ носит имя развёртывания (`.Values.name`); накат
			// — отдельный контейнер инициализации, и его здесь нет by construction.
			if cname != name {
				continue
			}
			res, _ := cm["resources"].(map[string]any)
			limits, _ := res["limits"].(map[string]any)
			v, ok := limits["memory"]
			if !ok {
				return 0, false, ""
			}
			raw = fmt.Sprint(v)
			parsed, err := parseMemoryQuantity(raw)
			require.NoErrorf(t, err, "resources.limits.memory контейнера службы = %q — величина не читается количеством Kubernetes", raw)
			return parsed, true, raw
		}
	}
	require.NotZerof(t, deployments, "обход пуст: Deployment в рендере не найден — вердикт беспредметен")
	// Сюда доходят только без совпадения по имени: контейнера службы в рендере нет.
	require.Failf(t, "обход пуст", "контейнер службы (имя развёртывания) не найден ни в одном из %d Deployment — вердикт беспредметен", deployments)
	return 0, false, ""
}

// parseMemoryQuantity — количество Kubernetes в байтах: целое без суффикса,
// двоичные суффиксы (Ki, Mi, Gi, Ti) и десятичные (k, M, G, T).
//
// Разбор СТРОГИЙ: незнакомая форма — отказ, а не ноль. Ноль читался бы как
// «предела нет», и опечатка в суффиксе становилась бы находкой не о том.
func parseMemoryQuantity(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("пустое количество")
	}
	suffixes := []struct {
		suffix string
		mult   uint64
	}{
		{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40},
		{"k", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12},
	}
	mult := uint64(1)
	num := s
	for _, sf := range suffixes {
		if strings.HasSuffix(s, sf.suffix) {
			mult = sf.mult
			num = strings.TrimSuffix(s, sf.suffix)
			break
		}
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("количество %q: %w", s, err)
	}
	return n * mult, nil
}

// loginLaneOfRender — величины полосы входа, какими их получит процесс: тело
// отрендеренной карты настроек грузится ТЕМ ЖЕ загрузчиком, что на старте.
func loginLaneOfRender(t *testing.T, rendered string) config.LoginLaneConfig {
	t.Helper()
	in := readRenderedInput(t, rendered)
	require.NoError(t, substituteRenderedSecrets(in), "заменители секретов рендера")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(in.ConfigBody), 0o600))
	requireCleanEnv(t)
	for k, v := range in.Envs {
		t.Setenv(k, v)
	}
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err, "отрендеренная карта настроек не загрузилась — вердикта о полосе нет")
	return cfg.AuthN.Login
}

// ownLaneMemoryCensus — объём осмотренного и величины арифметики: печатаются
// всегда, чтобы вердикт читался числами, а не словом.
type ownLaneMemoryCensus struct {
	Capacity     int
	PerCheck     uint64
	Reserve      uint64
	Need         uint64
	LimitRaw     string
	LimitBytes   uint64
	LimitDeclare bool
}

func (c ownLaneMemoryCensus) String() string {
	limit := "<не объявлен>"
	if c.LimitDeclare {
		limit = fmt.Sprintf("%s (%d байт)", c.LimitRaw, c.LimitBytes)
	}
	return fmt.Sprintf("ёмкость %d × %d байт на проверку + резерв %d = нужно %d байт · предел контейнера службы %s",
		c.Capacity, c.PerCheck, c.Reserve, c.Need, limit)
}

// judgeOwnLaneMemoryCeiling — ТЕЛО меры, вынесенное отдельно: инъекция зовёт
// то же, что исполняется на дереве. Вердикт выносит САМ страж полосы.
func judgeOwnLaneMemoryCeiling(login config.LoginLaneConfig, limit uint64, declared bool, raw string) (ownLaneMemoryCensus, error) {
	per := config.MemoryPerVerificationAtCeilingBytes()
	census := ownLaneMemoryCensus{
		Capacity: login.VerifierCapacity, PerCheck: per, Reserve: login.MemoryReserveBytes,
		LimitRaw: raw, LimitBytes: limit, LimitDeclare: declared,
	}
	if login.VerifierCapacity > 0 {
		census.Need = uint64(login.VerifierCapacity)*per + login.MemoryReserveBytes // #nosec G115 -- ёмкость проверена положительной строкой выше
	}
	return census, login.ValidateMemoryBudget(limit, declared)
}

// TestDeliveredChartDeclaresTheServiceContainerMemoryLimit — Р1.
func TestDeliveredChartDeclaresTheServiceContainerMemoryLimit(t *testing.T) {
	rendered := renderStandaloneChart(t, chartProfiles, minimalOperatorCoordinates...)
	bytes, declared, raw := memoryLimitOfServiceContainer(t, rendered)
	require.Truef(t, declared, "контейнер службы в рендере цепочки %v НЕ несёт `resources.limits.memory` — "+
		"под `own` страж полосы входа откажет в старте («предел памяти средой не наложен»), и "+
		"ни один профиль этого не выразит: шаблон не рендерит предел", chartProfiles)
	require.NotZero(t, bytes, "предел объявлен нулём — это «предела нет», а не предел")
	t.Logf("перепись: цепочка %v · контейнер службы · resources.limits.memory = %s (%d байт)", chartProfiles, raw, bytes)
}

// TestProdProfileMemoryLimitSatisfiesTheOwnLaneGuard — Р2.
func TestProdProfileMemoryLimitSatisfiesTheOwnLaneGuard(t *testing.T) {
	sets := withOwnPosture(minimalOperatorCoordinates...)
	rendered := renderStandaloneChart(t, chartProfiles, sets...)
	limit, declared, raw := memoryLimitOfServiceContainer(t, rendered)
	login := loginLaneOfRender(t, rendered)

	census, err := judgeOwnLaneMemoryCeiling(login, limit, declared, raw)
	t.Logf("перепись: %s", census)
	require.NoErrorf(t, err, "страж полосы входа отвергает вход, собранный поставляемой цепочкой %v под `own`: "+
		"профиль и страж говорят о разных числах — %s", chartProfiles, census)
	require.NotZero(t, census.Need, "нужда посчитана нулём — ёмкость полосы в рендере не прочитана, вердикт беспредметен")
}
