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
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// КОРНЕЙ, ОБЪЯВЛЯЮЩИХ ПОСАДКУ, ДВА — И ЭТО НЕ УДВОЕНИЕ (задача #2101).
//
// Профиль объявляет посадку в ДВУХ разных поставках, и правит их РАЗНЫЙ человек:
//
//	чарт продукта   — уезжает тому, кто ставит службу отдельно, без платформы;
//	                  его профили правит оператор чужого облака;
//	зонтичный чарт  — часть нашего стенда; его профили правим мы.
//
// До этой правки гейт читал ТОЛЬКО второй. Следствие измерено, а не
// предположено: посадка `own`, вписанная в боевой профиль ЧАРТА ПРОДУКТА,
// оставляла гейт зелёным — то есть слепая зона приходилась ровно на ту
// поставку, ради которой служба выносится отдельным продуктом.
//
// Подъёма каталогами здесь нет: число шагов вверх верно ровно для одной посадки.
const (
	// productChartDirRel — чарт ПРОДУКТА, координатой от корня МОДУЛЯ. Входит в
	// поставку модуля, поэтому читается в обеих посадках и пропуска не имеет.
	productChartDirRel = "deploy"
	// umbrellaDirRel — зонтичный чарт стенда, координатой от корня ПЛАТФОРМЫ. В
	// поставку модуля не входит by construction, поэтому его отсутствие —
	// «условие не создано», и оно НАЗЫВАЕТСЯ словами.
	umbrellaDirRel = "deploy/helm/umbrella"

	productRootName  = "чарт продукта"
	umbrellaRootName = "зонт платформы"
)

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

// profileSource — ОДИН файл значений, объявляющий полосу службе прав.
//
// Путь и КЛЮЧИ у корней разные: чарт продукта несёт `authn.identityProvider`
// верхним уровнем, зонтичный — под секцией службы. Второй перечень ключей рядом
// с первым разошёлся бы молча, поэтому ключи едут ВМЕСТЕ с путём, а не выбираются
// по имени корня в месте чтения.
type profileSource struct {
	// Root — имя корня. Печатается переписью: «ноль прочитанного у корня»
	// обязано быть отличимо от «корень ничего не объявляет».
	Root string
	// Label — КООРДИНАТА файла, по которой читатель находки его найдёт. Имена
	// файлов у корней совпадают (`values.prod.yaml` есть у обоих), поэтому голое
	// имя адресом не является и в находку идти не вправе.
	Label string
	Path  string
	Keys  []string
}

// rootCensus — объём осмотренного ПО КАЖДОМУ корню отдельно.
//
// Одно сводное число скрыло бы ровно тот случай, ради которого правка: корень,
// который не читали ВОВСЕ, даёт ту же сумму, что корень, ничего не объявивший.
type rootCensus struct {
	Root       string
	Seen       int
	Parsed     int
	Unreadable []string
}

// valuesFilesIn — файлы значений каталога, по возрастанию имени.
func valuesFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог значений %s не прочитан: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "values") || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// laneProfileSources — файлы значений ОБОИХ корней плюс оговорка о втором.
//
// Чарт продукта читается ВСЕГДА. Зонтичный — только там, где он есть; его
// отсутствие гасит ВТОРОЙ КОРЕНЬ, а не пробу целиком: погашенная проба
// перестала бы судить и продуктовый корень, то есть ровно тот, ради которого
// написана, — и в самостоятельном клоне у класса не осталось бы держателя
// вовсе.
func laneProfileSources(t *testing.T) (sources []profileSource, umbrellaNote string) {
	t.Helper()

	root, prefix := platformtree.RequireCorpus(t)
	productDir := filepath.Join(root, filepath.FromSlash(platformtree.Under(prefix, productChartDirRel)))
	for _, name := range valuesFilesIn(t, productDir) {
		sources = append(sources, profileSource{
			Root:  productRootName,
			Label: platformtree.Under(prefix, productChartDirRel+"/"+name),
			Path:  filepath.Join(productDir, name),
			Keys:  []string{"authn", "identityProvider"},
		})
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	umbrellaDir, err := platformtree.PathOf(wd, umbrellaDirRel)
	switch {
	case errors.Is(err, platformtree.ErrNoPlatformTree):
		return sources, "УСЛОВИЕ НЕ СОЗДАНО (не находка): " + err.Error()
	case err != nil:
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: зонтичный чарт не резолвится: %v", err)
	}
	for _, name := range valuesFilesIn(t, umbrellaDir) {
		sources = append(sources, profileSource{
			Root:  umbrellaRootName,
			Label: umbrellaDirRel + "/" + name,
			Path:  filepath.Join(umbrellaDir, name),
			Keys:  []string{"kaname", "config", "authn", "identityProvider"},
		})
	}
	// Базовое значение подчарта считается профилем — оно и есть умолчание
	// всякого стенда, не назвавшего полосу сам.
	const subchart = "charts/kaname/values.yaml"
	sources = append(sources, profileSource{
		Root:  umbrellaRootName,
		Label: umbrellaDirRel + "/" + subchart,
		Path:  filepath.Join(umbrellaDir, filepath.FromSlash(subchart)),
		Keys:  []string{"config", "authn", "identityProvider"},
	})
	return sources, ""
}

// readLaneDeclarations — «полоса → профили, её объявляющие» плюс перепись по
// корням.
//
// ТЕЛО чтения, вынесенное отдельно, чтобы инъекция звала то же, что исполняется
// на дереве: своя копия предиката разошлась бы с настоящим гейтом молча.
//
// Читаются ОБЪЯВЛЕНИЯ, а не рендер: рендер требует загруженных зависимостей и
// сети, а проба, умеющая пропускаться, гейтом не является.
func readLaneDeclarations(sources []profileSource) (map[string][]string, []rootCensus) {
	out := map[string][]string{}
	var census []rootCensus
	at := map[string]int{}

	for _, s := range sources {
		i, ok := at[s.Root]
		if !ok {
			i = len(census)
			at[s.Root] = i
			census = append(census, rootCensus{Root: s.Root})
		}
		census[i].Seen++
		lane, readable := nestedString(s.Path, s.Keys...)
		if !readable {
			census[i].Unreadable = append(census[i].Unreadable, s.Label)
			continue
		}
		census[i].Parsed++
		if lane == "" {
			continue
		}
		out[lane] = append(out[lane], s.Label)
	}
	for lane := range out {
		sort.Strings(out[lane])
	}
	return out, census
}

// profilesDeclaringALane — «полоса → профили» по дереву, с переписью и отказом
// на пустом обходе.
func profilesDeclaringALane(t *testing.T) map[string][]string {
	t.Helper()

	sources, umbrellaNote := laneProfileSources(t)
	if umbrellaNote != "" {
		t.Logf("%s: %s", umbrellaRootName, umbrellaNote)
	}
	out, census := readLaneDeclarations(sources)

	// ОБЪЁМ ОСМОТРЕННОГО, и обе его величины ПО КАЖДОМУ корню. На одном сводном
	// числе эта проверка уже обжигалась: профиль, который РАЗОБРАТЬ НЕ УДАЛОСЬ,
	// молча читался как «полосу не объявляет», и инъекция настоящим дефектом
	// осталась зелёной, ничего об этом не сказав.
	totalSeen, totalParsed, productParsed := 0, 0, 0
	for _, c := range census {
		totalSeen += c.Seen
		totalParsed += c.Parsed
		if c.Root == productRootName {
			productParsed += c.Parsed
		}
		t.Logf("перепись профилей [%s]: осмотрено %d · разобрано %d · не разобрано %d %v",
			c.Root, c.Seen, c.Parsed, len(c.Unreadable), c.Unreadable)
		if len(c.Unreadable) > 0 {
			t.Errorf("профили не разобраны %v — «не прочитан» НЕ означает «полосу не объявляет», "+
				"и молчаливое приравнивание одного к другому делает гейт слепым на этих файлах",
				c.Unreadable)
		}
	}
	t.Logf("перепись профилей ВСЕГО: корней %d · осмотрено %d · разобрано %d",
		len(census), totalSeen, totalParsed)

	if totalParsed == 0 {
		t.Fatal("обход пуст: ни один файл значений не разобран — гейт судил бы о непрочитанном")
	}
	// ПРЕДПОСЫЛКА, названная отдельно: продуктовый корень в поставку модуля
	// входит, поэтому «его не читали» — находка, а не посадка. Без этой строки
	// пропажа корня вернула бы слепую зону молча: зонтичных профилей хватило бы,
	// чтобы обход пустым не выглядел.
	if productParsed == 0 {
		t.Fatalf("обход чарта продукта пуст: ни один его файл значений не разобран, "+
			"а он входит в поставку модуля — гейт был бы слеп ровно на той поставке, "+
			"ради которой служба выносится отдельным продуктом (корень %q)", productRootName)
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
