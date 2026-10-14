// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// shipped_chains_declare_every_own_ceiling_test.go — КАЖДАЯ ПОСТАВЛЯЕМАЯ
// ЦЕПОЧКА ПРОФИЛЕЙ НАЗЫВАЕТ КАЖДЫЙ СОБСТВЕННЫЙ ПОТОЛОК (задача kaname#281).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Страж собственных потолков зовётся из `Config.Validate()` БЕЗУСЛОВНО — в
// любом режиме, а не только в боевом (`validate.go`, `own_ceilings.go`):
// незаданная величина роняет старт. Значит цепочка профилей, которая молчит
// хотя бы об одном потолке, описывает процесс, который не поднимется, — на
// какой бы посадке её ни читали.
//
// Замер, из которого проба выведена: потолок ключей доступа (Ф7) пришёл в
// таблицу, боевой профиль и шаблон, а стендовую накладку миновал. Проба стража
// старта судила ТОЛЬКО боевую цепочку (`TestProdProfile_SatisfiesTheBootGuard`),
// и пропуск не видела ни одна проба.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ И ЧЕМ
//
// Популяция — каждая цепочка, которую чарт предлагает (`chartChains`), и каждая
// цепочка «базовые значения + поставляемая накладка» из ведомости поставки
// (`deliveryRoster`): накладка, которую читают другие гейты как фикстуру, тоже
// объявляет конфигурацию службы, и фикстура неподнимаемого процесса судит не то.
//
// Вердикт — НАСТОЯЩИЙ загрузчик и НАСТОЯЩИЙ страж: цепочка перекладывается в
// файл настроек тем же переложением, что у пробы боевого профиля
// (`writeRenderedConfig`, верность шаблону держат `TestConfigBridge_*`), файл
// читает `config.Load`, а судит `Config.OwnCeilings.Validate()`. Перечня
// потолков проба не заводит: какие величины обязательны, знает страж, и
// пятый потолок, добавленный в таблицу, судится здесь без правки пробы.
//
// ЧЕМ ЭТО НЕ ЯВЛЯЕТСЯ: прочих разделов стража проба не судит. Стендовая накладка
// — фикстура открытого текста, и на остальных разделах она отказывает намеренно
// (см. её шапку и ведомость непредлагаемых профилей); здесь судится только
// раздел, у которого нет посадки, где он не действует.
package deploy_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// shippedChain — одна судимая цепочка: имя для отказа и слитые значения.
type shippedChain struct {
	Name   string
	Files  []string
	Merged map[string]any
}

// ownCeilingChainCensus — объём осмотренного, отдельно от находок.
type ownCeilingChainCensus struct {
	Chains   int // цепочек судимо
	Ceilings int // строк таблицы потолков, которые требует страж
	Rendered int // ключей `own-ceilings` положено во вход по всем цепочкам
}

func (c ownCeilingChainCensus) String() string {
	return fmt.Sprintf("цепочек судимо %d · потолков в таблице стража %d · "+
		"ключей own-ceilings положено во вход по всем цепочкам %d",
		c.Chains, c.Ceilings, c.Rendered)
}

// shippedChainsOf — популяция: предлагаемые цепочки и «база + накладка» по
// каждому поставляемому профилю. Одинаковый состав файлов судится один раз.
func shippedChainsOf(t *testing.T, offered map[string][]string, roster []string) []shippedChain {
	t.Helper()
	seen := map[string]bool{}
	var out []shippedChain
	add := func(name string, files []string) {
		key := strings.Join(files, "+")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, shippedChain{Name: name, Files: files, Merged: mergeChartProfiles(t, files)})
	}
	for name, files := range offered {
		add(name, files)
	}
	for _, f := range roster {
		if f == chartDefaultsFile || !strings.HasPrefix(f, "values.") || !strings.HasSuffix(f, ".yaml") {
			continue
		}
		add(f, []string{chartDefaultsFile, f})
	}
	return out
}

// judgeChainOwnCeilings — тело пробы, вынесенное ради инъекции: входы приходят
// параметрами, пустая популяция — отказ обхода, а не зелёное.
func judgeChainOwnCeilings(t *testing.T, chains []shippedChain) (findings []string, census ownCeilingChainCensus) {
	t.Helper()
	require.NotEmpty(t, chains, "обход пуст: ни одной цепочки профилей — вердикт беспредметен")
	require.NotEmpty(t, config.OwnCeilingKnobs,
		"таблица потолков пуста — страж не требует ничего, и зелёное ничего не значит")
	census.Ceilings = len(config.OwnCeilingKnobs)

	for _, ch := range chains {
		census.Chains++
		t.Run(ch.Name, func(t *testing.T) {
			// Переменные, поставленные здесь, живут до конца ПОДпробы: у каждой
			// цепочки своё окружение, и вердикт одной не протекает в другую.
			requireCleanEnv(t)
			envs := envEntries(ch.Merged)
			for k, v := range envs {
				t.Setenv(k, v)
			}
			cfgPath, _ := writeRenderedConfig(t, ch.Merged)
			if m, ok := at(ch.Merged, "ownCeilings").(map[string]any); ok {
				census.Rendered += len(m)
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				findings = append(findings, fmt.Sprintf(
					"  цепочка %s (%s): конфигурация не загрузилась: %v",
					ch.Name, strings.Join(ch.Files, " + "), err))
				return
			}
			for _, e := range multierr.Errors(cfg.OwnCeilings.Validate()) {
				findings = append(findings, fmt.Sprintf(
					"  цепочка %s (%s): %v",
					ch.Name, strings.Join(ch.Files, " + "), e))
			}
		})
	}
	return findings, census
}

func TestEveryShippedChainDeclaresEveryOwnCeiling(t *testing.T) {
	chains := shippedChainsOf(t, chartChains, deliveryRoster)
	findings, census := judgeChainOwnCeilings(t, chains)
	t.Logf("перепись: %s", census)
	require.Emptyf(t, findings,
		"цепочка профилей молчит о собственном потолке — страж старта откажет в пуске на "+
			"ЛЮБОЙ посадке, потому что умолчания у потолка нет. Объявите величину в накладке "+
			"(блок `ownCeilings`); 0 законен и означает «ресурсов этого вида не заводить».\n%s",
		strings.Join(findings, "\n"))
}
