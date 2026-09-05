// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_profile_coverage_test.go — ГЕЙТ КЛАССА: полоса посадки личности, которую
// процесс УМЕЕТ поднять, обязана быть объявлена профилем развёртывания; полоса,
// объявленная профилем, обязана подниматься.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ «ЛИБО ПРОФИЛЬ, ЛИБО НЕДОСТИЖИМОСТЬ», А НЕ ПРОСТО «ПРОФИЛЬ»
//
// Требование «у каждой полосы есть профиль» в чистом виде чинится профилем,
// который не поднимается, — то есть обещанием. Это ровно тот класс, который
// корпус ловит: возможность объявлена и неисполнима. Поэтому гейт судит ПАРУ и
// краснеет на обоих её перекосах:
//
//	достижима и не объявлена  → полосу умеют поднять, и ею никто не пользуется;
//	                            арендатор о ней не узнает ниоткуда;
//	объявлена и недостижима   → профиль обещает посадку, которую процесс
//	                            отвергнет при старте.
//
// Совпадение (обе достижимы и объявлены, либо обе нет) — молчание. И во ВТОРОМ
// случае молчание не пустое: перепись печатает ОТКАЗ, которым процесс объясняет
// недостижимость, поэтому «полосы own нет ни в одном профиле» никогда не
// выглядит как недосмотр.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДОСТИЖИМОСТЬ СУДИТСЯ НА СТАДИИ СБОРКИ, А НЕ НАСТРОЙКИ — И ЭТО РЕЗ, А НЕ ВКУС
//
// Требования стадии НАСТРОЙКИ выполняет ОПЕРАТОР: три адреса поставщика он
// впишет в профиль, и достижимость по ним есть свойство профиля, а не дерева.
// Требования стадии СБОРКИ выполняем МЫ: их значения приходят из
// композиционного корня, и профиль на них не влияет НИКАК. Полоса, чьи
// требования сборки корень выполнить не может, недостижима BY CONSTRUCTION —
// сколько бы ни писал оператор.
//
// ─────────────────────────────────────────────────────────────────────────────
// САМОИСТЕЧЕНИЕ
//
// Ведомости прощённых здесь нет намеренно: её пришлось бы вести руками, и она
// пережила бы свой предмет. Вместо неё — предикат. В тот день, когда
// композиционный корень научится выполнять требования сборки полосы `own`,
// она станет достижимой, и гейт ПОТРЕБУЕТ профиль сам, ничего не спрашивая.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕЧЕНЬ ПОЛОС ВЫВОДИТСЯ ИЗ ТАБЛИЦЫ ТРЕБОВАНИЙ
//
// Не из словаря значений и не выписыванием: рукописный перечень разошёлся бы с
// таблицей молча — и разошёлся бы на полосе, которую в него забыли дописать.
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// umbrellaDirFromCmd — каталог зонтичного чарта относительно этого пакета.
const umbrellaDirFromCmd = "../../../../deploy/helm/umbrella"

// laneFact — что известно об ОДНОЙ полосе.
type laneFact struct {
	Lane string
	// Profiled — хотя бы один профиль развёртывания объявляет эту полосу службе
	// прав.
	Profiled bool
	// ProfileNames — какие именно. Печатается переписью: «объявлена» без имени
	// не проверяемо читателем.
	ProfileNames []string
	// Reachable — композиционный корень выполняет требования СБОРКИ этой полосы.
	Reachable bool
	// Refusal — чем именно корень отказывает, когда не выполняет. Пусто у
	// достижимой полосы.
	Refusal string
}

// judgeLaneCoverage — ТЕЛО гейта, вынесенное отдельно, чтобы инъекция звала то
// же, что исполняется на дереве. Своя копия предиката в инъекции разошлась бы с
// настоящим гейтом молча.
func judgeLaneCoverage(facts []laneFact) (profiled, reachable int, findings []string) {
	for _, f := range facts {
		if f.Profiled {
			profiled++
		}
		if f.Reachable {
			reachable++
		}
		switch {
		case f.Reachable && !f.Profiled:
			findings = append(findings, "полоса "+f.Lane+": процесс её поднимает, и НИ ОДИН профиль "+
				"развёртывания её не объявляет — возможность есть, и узнать о ней арендатору неоткуда")
		case !f.Reachable && f.Profiled:
			findings = append(findings, "полоса "+f.Lane+": её объявляют профили ["+
				strings.Join(f.ProfileNames, ", ")+"], а композиционный корень отвергает её при "+
				"старте — профиль обещает посадку, которой не будет. Отказ: "+f.Refusal)
		}
	}
	return profiled, reachable, findings
}

// Гейт по дереву.
func TestEveryLaneIsEitherProfiledOrProvablyUnreachable(t *testing.T) {
	facts := collectLaneFacts(t)
	if len(facts) == 0 {
		t.Fatal("обход пуст: таблица требований не назвала ни одной полосы — гейт судил бы о непрочитанном")
	}

	profiled, reachable, findings := judgeLaneCoverage(facts)
	t.Logf("перепись: полос в таблице требований %d · объявлены профилями %d · поднимаются корнем %d · находок %d",
		len(facts), profiled, reachable, len(findings))
	for _, f := range facts {
		switch {
		case f.Reachable:
			t.Logf("  %s: поднимается · профили [%s]", f.Lane, strings.Join(f.ProfileNames, ", "))
		default:
			// Отказ печатается ВСЕГДА: «профиля нет» обязано быть отличимо от
			// «профиль забыли», и различает их ровно этот текст.
			t.Logf("  %s: НЕ поднимается · профили [%s] · отказ: %s",
				f.Lane, strings.Join(f.ProfileNames, ", "), f.Refusal)
		}
	}

	for _, f := range findings {
		t.Error(f)
	}
}

// collectLaneFacts — перечень полос из таблицы требований плюс два факта о
// каждой.
func collectLaneFacts(t *testing.T) []laneFact {
	t.Helper()

	seen := map[config.IdentityProvider]bool{}
	var lanes []config.IdentityProvider
	for _, r := range config.LaneRequirements {
		for _, l := range r.Lanes {
			if !seen[l] {
				seen[l] = true
				lanes = append(lanes, l)
			}
		}
	}
	sort.Slice(lanes, func(i, j int) bool { return lanes[i].String() < lanes[j].String() })

	declared := profilesDeclaringALane(t)
	best := bestCaseWiring(t)

	out := make([]laneFact, 0, len(lanes))
	for _, l := range lanes {
		cfg := config.Config{}
		cfg.AuthN.Mode = config.ModeProduction
		cfg.AuthN.IdentityProvider = l
		// Строка «своя чеканка включена» — стадии НАСТРОЙКИ, её выполняет
		// профиль; здесь судится только стадия СБОРКИ.
		cfg.AuthN.TokenSigning.Enabled = true

		f := laneFact{Lane: l.String(), ProfileNames: declared[l.String()]}
		f.Profiled = len(f.ProfileNames) > 0
		if err := config.ValidateLaneWiring(cfg, best); err != nil {
			f.Refusal = strings.ReplaceAll(err.Error(), "\n", " | ")
		} else {
			f.Reachable = true
		}
		out = append(out, f)
	}
	return out
}

// bestCaseWiring — НАИЛУЧШАЯ проводка, которую композиционный корень способен
// произвести.
//
// Берётся его собственная функция наблюдения, и ровно один факт подаётся в
// лучшем виде: подписант своей чеканки. Он — единственная величина проводки,
// которой распоряжается ПРОФИЛЬ (включил чеканку — корень поднял подписанта),
// и оставить её наблюдённой значило бы объявить полосу недостижимой из-за
// настройки, а не из-за дерева. Остальные величины корень решает один, и они
// берутся как есть.
func bestCaseWiring(t *testing.T) config.LaneWiring {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := observeLaneWiring(context.Background(), nil, logger)
	w.OwnMintSignerWired = true
	return w
}

// profilesDeclaringALane — «полоса → профили, её объявляющие».
//
// Читаются ОБЪЯВЛЕНИЯ, а не рендер: рендер зонта требует загруженных
// зависимостей и сети, а проба, умеющая пропускаться, гейтом не является.
// Базовое значение подчарта считается профилем — оно и есть умолчание всякого
// стенда, не назвавшего полосу сам.
func profilesDeclaringALane(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}

	add := func(lane, profile string) {
		if lane == "" {
			return
		}
		out[lane] = append(out[lane], profile)
	}

	entries, err := os.ReadDir(umbrellaDirFromCmd)
	if err != nil {
		t.Fatalf("каталог зонтичного чарта не прочитан: %v", err)
	}
	seen, parsed := 0, 0
	var unreadable []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "values") || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		seen++
		lane, ok := nestedString(filepath.Join(umbrellaDirFromCmd, name),
			"kacho-iam", "config", "authn", "identityProvider")
		if !ok {
			unreadable = append(unreadable, name)
			continue
		}
		parsed++
		add(lane, name)
	}

	const subchart = "charts/kacho-iam/values.yaml"
	seen++
	if lane, ok := nestedString(filepath.Join(umbrellaDirFromCmd, subchart),
		"config", "authn", "identityProvider"); ok {
		parsed++
		add(lane, subchart)
	} else {
		unreadable = append(unreadable, subchart)
	}

	// ОБЪЁМ ОСМОТРЕННОГО, и обе его величины. Одно число «профилей N» скрыло бы
	// ровно тот случай, на котором эта проверка сама и обожглась: профиль,
	// который РАЗОБРАТЬ НЕ УДАЛОСЬ, молча читался как «полосу не объявляет», и
	// инъекция настоящим дефектом осталась зелёной, ничего об этом не сказав.
	t.Logf("перепись профилей: осмотрено %d · разобрано %d · не разобрано %d %v",
		seen, parsed, len(unreadable), unreadable)
	if parsed == 0 {
		t.Fatal("обход пуст: ни один файл значений не разобран — гейт судил бы о непрочитанном")
	}
	if len(unreadable) > 0 {
		t.Errorf("профили не разобраны %v — «не прочитан» НЕ означает «полосу не объявляет», "+
			"и молчаливое приравнивание одного к другому делает гейт слепым на этих файлах",
			unreadable)
	}

	for lane := range out {
		sort.Strings(out[lane])
	}
	return out
}

// nestedString достаёт строковое значение по пути ключей.
//
// Второе возвращаемое значение отделяет «файл прочитан и полосы в нём нет» от
// «файл прочитать не удалось». Различие несущее: без него неразобранный профиль
// читается как необъявляющий, и гейт становится слеп ровно на тех файлах, где
// что-то не так. На этом обжёгся сам автор — инъекция настоящим дефектом
// осталась зелёной, потому что вносила его в файл, который после правки
// перестал разбираться.
func nestedString(path string, keys ...string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", false
	}
	var cur any = doc
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", true
		}
		if cur, ok = m[k]; !ok {
			return "", true
		}
	}
	s, _ := cur.(string)
	return s, true
}
