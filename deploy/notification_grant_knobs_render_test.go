// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notification_grant_knobs_render_test.go — ДВЕ РУЧКИ СЛУЖБЫ ВЫДАЧИ
// УВЕДОМЛЕНИЙ, КОТОРЫЕ ЧАРТ ОБЯЗАН ОТДАВАТЬ ПРОЦЕССУ (приёмка NTF-1 Р2, Р5;
// решение Д112 (в)).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Служба выдачи (`InternalNotificationGrantService`) собирается корнем
// БЕЗУСЛОВНО, и её строитель отказывает в старте без полосы отсечки
// `notifications.cutoff-guard`: умолчания у неё нет ни у процесса, ни у чарта
// (граница [1s..10m], NTF1-F20). Чарт ключа не рендерил — и служба не
// стартовала ни в одном профиле, а проба боевого профиля была зелёной: её
// сводный вердикт судил `Config.Validate()`, а этот страж стоит в стадии
// СБОРКИ. Отсюда три утверждения:
//
//	П1  каждый поставляемый профиль объявляет полосу ЯВНО, рендер отдаёт её
//	    ключом `notifications.cutoff-guard`, и строитель службы её принимает
//	    (судится тем же `CutoffGuardValue`, который зовёт строитель);
//	П2  пустая, снятая или не-длительность — ОТКАЗ РЕНДЕРА с именем ручки
//	    (`notifications.cutoffGuard`), а не дословная подстановка;
//	П3  блок `serviceIdentity: {methods, services}` → ключ
//	    `authn.service-identity`: согласный блок рендерится и принимается
//	    процессом; задана половина — отказ рендера с именем ручки; блок пуст
//	    либо не задан — ключа нет (звено `NotApplicable`, fail-closed).
//
// Чего проба НЕ утверждает: пода она не поднимает. Подъём — стенды
// (`.github/scripts/stand-own.sh`, `.github/scripts/stand-chart.sh`).
package deploy_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// cutoffGuardValueKnob — ручка значений чарта. Её называет отказ рендера.
const cutoffGuardValueKnob = "notifications.cutoffGuard"

// serviceIdentityValueKnob — блок значений звена Р2 (S11 NTF-2, CX1-108).
const serviceIdentityValueKnob = "serviceIdentity"

// resolveSendMethod — единственный метод закрытого перечня звена в kaname.
const resolveSendMethod = "kaname.cloud.iam.v1.InternalNotificationGrantService/ResolveSend"

// suppliedProfileChains — цепочки «базовые значения + поставляемый профиль»
// по КАЖДОМУ файлу `values.*.yaml` каталога. Перечень выводится из каталога,
// а не выписывается: профиль, добавленный завтра, попадает под пробу сам.
func suppliedProfileChains(t *testing.T) [][]string {
	t.Helper()
	files, err := filepath.Glob("values.*.yaml")
	require.NoError(t, err)
	sort.Strings(files)
	var chains [][]string
	for _, f := range files {
		chains = append(chains, []string{"values.yaml", f})
	}
	require.NotEmpty(t, chains, "в каталоге чарта нет ни одного поставляемого профиля — обход пуст, вердикта нет")
	return chains
}

// cutoffGuardOf — полоса, как её примет строитель службы выдачи: тело
// настроек рендера → `config.Load` → `CutoffGuardValue`.
func cutoffGuardOf(t *testing.T, body string) (string, error) {
	t.Helper()
	requireCleanEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err, "тело настроек рендера не загрузилось")
	g, err := cfg.Notifications.CutoffGuardValue()
	return g.String(), err
}

// ── П1 ───────────────────────────────────────────────────────────────────────

func TestCutoffGuard_EverySuppliedProfileDeclaresItAndTheBuilderAcceptsIt(t *testing.T) {
	chains := suppliedProfileChains(t)
	for _, chain := range chains {
		out := renderStandaloneChart(t, chain)
		in := readRenderedInput(t, out)
		tree := renderedConfigTree(t, out)
		rendered := configString(tree, config.CutoffGuardKey)
		require.NotEmptyf(t, rendered, "цепочка %v: ключа %s в карте настроек нет — строитель службы "+
			"выдачи откажет в старте", chain, config.CutoffGuardKey)
		g, err := cutoffGuardOf(t, in.ConfigBody)
		require.NoErrorf(t, err, "цепочка %v: полоса отрендерена, а строитель её отвергает", chain)
		t.Logf("цепочка %v: %s = %s → строитель принял %s", chain, config.CutoffGuardKey, rendered, g)
	}
	t.Logf("перепись: поставляемых профилей %d", len(chains))
}

// Отрицательный контроль П1: тело без ключа строитель ОБЯЗАН отвергать — иначе
// утверждение П1 о его согласии ничего не стоит.
func TestCutoffGuard_BuilderRefusesABodyWithoutTheKey(t *testing.T) {
	in := readRenderedInput(t, renderStandaloneChart(t, chartProfiles))
	var kept []string
	dropped := 0
	for _, line := range strings.Split(in.ConfigBody, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "cutoff-guard:") {
			dropped++
			continue
		}
		kept = append(kept, line)
	}
	require.Equal(t, 1, dropped, "в рендере боевого профиля строк полосы не ровно одна — контролю снимать нечего")
	_, err := cutoffGuardOf(t, strings.Join(kept, "\n"))
	require.Error(t, err, "тело без полосы принято строителем — П1 судит молчащего стража")
	require.Contains(t, err.Error(), config.CutoffGuardKey)
}

// ── П2 ───────────────────────────────────────────────────────────────────────

func TestCutoffGuard_EmptyOrMalformedValueRefusesTheRender(t *testing.T) {
	for _, set := range []string{
		cutoffGuardValueKnob + "=",
		cutoffGuardValueKnob + "=null",
		cutoffGuardValueKnob + "=soon",
		cutoffGuardValueKnob + "=0s",
	} {
		t.Run(set, func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, set)
			requireRenderRefusal(t, out, err, cutoffGuardValueKnob)
		})
	}
	// Близнец: законная величина рендерится дословно.
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, cutoffGuardValueKnob+"=45s")
	require.NoErrorf(t, err, "законная полоса отвергнута рендером:\n%s", headOf(out))
	require.Equal(t, "45s", configString(renderedConfigTree(t, out), config.CutoffGuardKey))
}

// ── П3 ───────────────────────────────────────────────────────────────────────

const consistentServiceIdentity = "serviceIdentity.methods[0]=" + resolveSendMethod +
	",serviceIdentity.services[0].san=spiffe://kaname.example.invalid/ns/notify/sa/notify" +
	",serviceIdentity.services[0].name=notify"

func TestServiceIdentity_ConsistentBlockRendersTheKeyTheProcessReads(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, consistentServiceIdentity)
	require.NoErrorf(t, err, "согласный блок отвергнут рендером:\n%s", headOf(out))
	in := readRenderedInput(t, out)

	requireCleanEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(in.ConfigBody), 0o600))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err, "тело с ключом %s не загрузилось", config.ServiceIdentityKey)
	si := cfg.AuthN.ServiceIdentity
	require.Equal(t, []string{resolveSendMethod}, si.Methods)
	require.Equal(t, []config.ServiceIdentityEntry{{
		SAN: "spiffe://kaname.example.invalid/ns/notify/sa/notify", Name: "notify",
	}}, si.Services)
	t.Logf("%s: методов %d · строк таблицы %d", config.ServiceIdentityKey, len(si.Methods), len(si.Services))
}

func TestServiceIdentity_HalfBlockRefusesTheRender(t *testing.T) {
	for _, set := range []string{
		"serviceIdentity.methods[0]=" + resolveSendMethod,
		"serviceIdentity.services[0].san=spiffe://kaname.example.invalid/ns/notify/sa/notify,serviceIdentity.services[0].name=notify",
		consistentServiceIdentity + ",serviceIdentity.services[0].san=",
		consistentServiceIdentity + ",serviceIdentity.services[0].name=",
	} {
		t.Run(set, func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, set)
			requireRenderRefusal(t, out, err, serviceIdentityValueKnob)
		})
	}
}

func TestServiceIdentity_EmptyBlockRendersNoKey(t *testing.T) {
	tree := renderedConfigTree(t, renderStandaloneChart(t, chartProfiles))
	require.Nil(t, at(tree, "authn", "service-identity"),
		"блок %s не задан, а ключ %s отрендерен", serviceIdentityValueKnob, config.ServiceIdentityKey)
	// Контроль: тот же рендер с согласным блоком ключ несёт — иначе «ключа нет»
	// зеленело бы и на шаблоне, который его не рендерит никогда.
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, consistentServiceIdentity)
	require.NoError(t, err)
	require.NotNil(t, at(renderedConfigTree(t, out), "authn", "service-identity"))
}
