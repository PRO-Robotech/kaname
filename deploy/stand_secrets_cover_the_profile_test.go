// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// stand_secrets_cover_the_profile_test.go — КАЖДЫЙ КЛЮЧ СЕКРЕТА, КОТОРЫЙ
// ПОСТАВЛЯЕМЫЙ ПРОФИЛЬ ОБЪЯВЛЯЕТ ПОДУ, СТЕНД ЧАРТА ЗАВОДИТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (найдено по дороге kaname#21, 2026-09-17)
//
// Боевой профиль объявляет переменные, приезжающие из объекта Secret, картой
// `secrets` — именем объекта и ключом в нём. Шаблон развёртывания рендерит их
// `secretKeyRef` БЕЗ `optional`: ключа в объекте нет — контейнер не создаётся
// вовсе (`CreateContainerConfigError: couldn't find key … in Secret …`), и
// выкат не доходит до готовности. Стенд чарта (`.github/scripts/stand-chart.sh`,
// `make_secrets`) заводит объект `<релиз>-authn` сам, перечнем ключей в
// исполняемой строке скрипта.
//
// Замер: фаза Ф12 добавила в карту `secrets` третью переменную
// (`KANAME_SECOND_FACTOR_ENC_KEY` ← `second-factor-encryption-key-hex`), а стенд
// продолжал заводить два ключа. Подъём чарта на голове линии — как его гоняет
// конвейер, посадка `external` — встал на первом же поде:
//
//	Error: couldn't find key second-factor-encryption-key-hex in Secret kaname/kaname-authn
//
// Прогона задания `chart` после того слияния не было ни одного, и красное
// лежало в дереве незамеченным: два места об одном перечне разошлись молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	Р1  для каждой записи карты `secrets` поставляемой цепочки с именем объекта,
//	    который стенд заводит сам, ключ этой записи стоит в исполняемой строке
//	    `--from-literal=<ключ>=` либо `--from-file=<ключ>=` того же объекта;
//	Р2  перепись печатается величинами: записей профиля · ключей стенда ·
//	    находок; пустой обход — отказ.
//
// Лишний ключ у стенда находкой НЕ является: пода он не ломает.
//
// Скрипт читается по ИСПОЛНЯЕМЫМ строкам: имя ключа встречается и в комментариях
// (в том числе в этом объяснении внутри скрипта), и разбор по подстроке считал
// бы прозу заведением.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// standChartScriptRel — стенд чарта, от корня дерева.
const standChartScriptRel = ".github/scripts/stand-chart.sh"

// standReleaseVar — как скрипт называет релиз в именах объектов.
const standReleaseVar = "$RELEASE"

// standReleaseDefault — умолчание релиза в скрипте; профиль называет объекты
// этим именем буквально.
const standReleaseDefault = "kaname"

var (
	createSecretRe = regexp.MustCompile(`create secret generic "([^"]+)"`)
	fromKeyRe      = regexp.MustCompile(`--from-(?:literal|file)=([A-Za-z0-9._-]+)=`)
)

// secretRef — запись карты `secrets` профиля.
type secretRef struct {
	Env, Name, Key, Profile string
}

// profileSecretRefs — записи карты `secrets` по цепочке профилей; поздний
// профиль перебивает ранний той же переменной, как это делает helm.
func profileSecretRefs(t *testing.T, chartDir string, chain []string) []secretRef {
	t.Helper()
	byEnv := map[string]secretRef{}
	for _, name := range chain {
		raw, err := os.ReadFile(filepath.Join(chartDir, name)) // #nosec G304 -- имя из перечня в дереве
		require.NoErrorf(t, err, "профиль %s не читается", name)
		var tree map[string]any
		require.NoErrorf(t, yaml.Unmarshal(raw, &tree), "профиль %s не разбирается", name)
		secrets, _ := tree["secrets"].(map[string]any)
		for env, v := range secrets {
			coord, _ := v.(map[string]any)
			n, _ := coord["secretName"].(string)
			k, _ := coord["secretKey"].(string)
			byEnv[env] = secretRef{Env: env, Name: n, Key: k, Profile: name}
		}
	}
	out := make([]secretRef, 0, len(byEnv))
	for _, r := range byEnv {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Env < out[j].Env })
	return out
}

// standSecretKeys — ключи, которые стенд кладёт в КАЖДЫЙ заводимый им объект:
// имя объекта (с подставленным умолчанием релиза) → ключи. Читаются
// исполняемые строки: комментарии и пустые пропускаются, продолжение команды
// через `\` собирается в одну.
func standSecretKeys(t *testing.T, root string) (keys map[string][]string, linesRead int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, standChartScriptRel)) // #nosec G304 -- координата в дереве
	require.NoError(t, err, "стенд чарта не читается")
	keys = map[string][]string{}
	var cmd strings.Builder
	flush := func() {
		line := cmd.String()
		cmd.Reset()
		m := createSecretRe.FindStringSubmatch(line)
		if m == nil {
			return
		}
		name := strings.ReplaceAll(m[1], standReleaseVar, standReleaseDefault)
		for _, km := range fromKeyRe.FindAllStringSubmatch(line, -1) {
			keys[name] = append(keys[name], km[1])
		}
	}
	for _, l := range strings.Split(string(raw), "\n") {
		linesRead++
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, "\\") {
			cmd.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cmd.WriteString(" ")
			continue
		}
		cmd.WriteString(trimmed)
		flush()
	}
	return keys, linesRead
}

// judgeStandSecretsCoverTheProfile — ТЕЛО меры: инъекция зовёт то же.
func judgeStandSecretsCoverTheProfile(refs []secretRef, standKeys map[string][]string) (findings []string, refsJudged int) {
	for _, r := range refs {
		created, standMakesIt := standKeys[r.Name]
		if !standMakesIt {
			// Объект, который стенд не заводит (пароль базы в `<релиз>-db` он
			// заводит; чужие объекты — не его предмет и здесь не судятся).
			continue
		}
		refsJudged++
		found := false
		for _, k := range created {
			if k == r.Key {
				found = true
				break
			}
		}
		if !found {
			findings = append(findings, fmt.Sprintf("%s (профиль %s): переменная %s ждёт ключ %q в объекте %s, "+
				"а стенд заводит его с ключами [%s] — под встанет в CreateContainerConfigError",
				r.Env, r.Profile, r.Env, r.Key, r.Name, strings.Join(created, ", ")))
		}
	}
	return findings, refsJudged
}

func TestStandChartCreatesEverySecretKeyTheProfileDeclares(t *testing.T) {
	root := serviceRoot(t)
	refs := profileSecretRefs(t, filepath.Join(root, "deploy"), chartProfiles)
	standKeys, linesRead := standSecretKeys(t, root)
	require.NotEmpty(t, refs, "карта `secrets` цепочки %v пуста — обход пуст, вердикт беспредметен", chartProfiles)
	require.NotEmpty(t, standKeys, "стенд не заводит ни одного объекта Secret (прочитано строк %d) — обход пуст", linesRead)

	findings, judged := judgeStandSecretsCoverTheProfile(refs, standKeys)
	require.NotZero(t, judged, "ни одна запись профиля не адресует объект, который стенд заводит, — судить нечего")
	t.Logf("перепись: записей карты secrets %d · из них об объектах стенда %d · объектов стенда %d · строк скрипта %d · находок %d",
		len(refs), judged, len(standKeys), linesRead, len(findings))
	for _, f := range findings {
		t.Error(f)
	}
}
