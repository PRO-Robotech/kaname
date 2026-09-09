// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_routes_every_surface_test.go — КАЖДАЯ поверхность, которую поднимает
// процесс, несёт маршрут; и маршрут этот ведёт туда, куда она поднята.
//
// # Предмет
//
// Профиль объявлял службе восемь дверей и вёл к двум (задача #2337). Заметить
// это по чарту было нельзя: каждое из двух объявлений — адрес фронта в профиле и
// порт в шаблоне — по отдельности верно, а расхождение двух ручек об одной двери
// молчит by construction.
//
// Следствие для клиента разное у каждой полосы и ни одно не косметическое:
// докерный клиент не доходит до выдачи токена, которую документ установки
// обещает внешне достижимой; плоскость данных реестра не берёт ключи проверки, и
// её верификация остаётся закрытой; поставщик личности не доносит вебхуки, то
// есть вход по первому обращению не заводит пользователя; а собственный
// публичный REST-фронт — единственная тенантская HTTP-дверь отдельно
// поставленной службы — существует внутри пода.
//
// # Что здесь утверждается
//
//	Р1  перечень поверхностей ВЫВЕДЕН из объявлений процесса, а не выписан;
//	Р2  у каждой поверхности есть маршрут, и он ведёт на её адрес;
//	Р3  маршрут ведёт на объект, отвечающий ДОСЯГАЕМОСТИ поверхности: служебная
//	    дверь на публичном объекте — расширение периметра, которого не решал
//	    никто (запрет #6);
//	Р4  перепись печатается ДВУМЯ величинами.
//
// # Почему досягаемость — тоже предмет гейта
//
// Единственный рычаг, которым оператор выводит службу наружу, — тип объекта
// Service. Пока публичные и служебные двери сидят на одном объекте, этот рычаг
// двигает их вместе, и периметр расширяется объектом развёртывания, а не строкой
// кода. Гейт, судящий только «есть ли порт», разрешил бы ровно это.
//
// # Область
//
// Судится ОБЪЯВЛЕНИЕ чарта. Поднятия пода здесь нет: свободного кластера нет, и
// это третья категория — не зелёное и не красное.
package deploy_test

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// routedSurface — поверхность и найденный ей маршрут.
type routedSurface struct {
	surface surfaceroster.Surface
	// port — адрес, по которому её поднимет процесс с этим входом.
	port string
	// via — чем именно она досягаема: имя объекта Service либо объявление сбора.
	via string
	// why — почему маршрута нет, если его нет.
	why string
}

// scrapeRoute — имя маршрута диагностической поверхности.
//
// Её маршрут — ОБЪЯВЛЕНИЕ СБОРА, а не порт Service: собиратель платформы ходит
// по подам. Порт Service ей не нужен ни для чего, и открытая дверь без
// потребителя была бы расширением поверхности, ничего не дающим.
const scrapeRoute = "объявление сбора (prometheus.io/*)"

func TestServiceRoutesEverySurfaceItRaises(t *testing.T) {
	roster := readSurfaceRoster(t)
	rendered := renderStandaloneChart(t, []string{"values.yaml", "values.prod.yaml"})
	raised, routed, findings := judgeSurfaceRoutes(t, roster, rendered)
	require.Emptyf(t, findings,
		"поверхностей поднято %d · с маршрутом %d; не ведёт маршрут к %d:\n  - %s",
		raised, routed, len(findings), strings.Join(findings, "\n  - "))
}

// readSurfaceRoster — перечень поверхностей процесса. Отдельной функцией, чтобы
// доказательство способности гейта упасть читало ТОТ ЖЕ перечень.
func readSurfaceRoster(t *testing.T) surfaceroster.Roster {
	t.Helper()
	root, err := surfaceroster.IAMRoot(".")
	require.NoError(t, err, "корень дерева службы")
	roster, err := surfaceroster.Read(root)
	require.NoError(t, err, "перечень поверхностей")
	require.NotEmpty(t, roster.Surfaces,
		"перечень поверхностей пуст — вердикт был бы о пустоте, а не о дереве")
	return roster
}

// judgeSurfaceRoutes — САМО СУЖДЕНИЕ, отделённое от пробы: доказательство
// способности упасть обязано звать его же, иначе оно доказывало бы о своей
// копии, а не о гейте.
func judgeSurfaceRoutes(t *testing.T, roster surfaceroster.Roster, rendered string) (int, int, []string) {
	t.Helper()
	cfg := renderedConfigTree(t, rendered)
	svcPorts, svcTypes := renderedServicePorts(t, rendered)
	container := renderedContainerPorts(t, rendered)
	scrape := renderedScrapeDeclared(t, rendered)

	require.NoError(t, routeSourcesPresent(svcPorts, scrape), "предпосылка гейта")

	var routed, raised int
	var findings []string
	var lines []string

	for _, s := range roster.Surfaces {
		addr := configString(cfg, s.SettingKey)
		if addr == "" {
			addr = s.DefaultAddr
		}
		if addr == "" {
			// Поверхность НЕ ПОДНЯТА этим входом: умолчания у адреса нет, и
			// посадка его не назвала. Вести к ней нечем, и это не находка —
			// процесс говорит об этом сам при старте.
			lines = append(lines, fmt.Sprintf("  %-38s не поднята этим входом (адреса нет)", s.SettingKey))
			continue
		}
		raised++

		r := routedSurface{surface: s, port: portOfAddr(addr)}
		switch {
		case s.SettingKey == "api-server.metrics-endpoint":
			if scrape.enabled && scrape.port == r.port {
				r.via = scrapeRoute
			} else if !scrape.enabled {
				r.why = "сбор выключен, и порта Service у диагностики нет: величины производятся и не снимаются никем"
			} else {
				r.why = fmt.Sprintf("объявление сбора называет порт %s, а процесс поднимает поверхность на %s: агент придёт не туда", scrape.port, r.port)
			}
		default:
			want := publicServiceName
			if s.Reach == "cluster-internal" {
				want = internalServiceName
			}
			switch {
			case svcPorts[want][r.port]:
				r.via = want
			case svcPorts[otherService(want)][r.port]:
				r.why = fmt.Sprintf("маршрут есть, но ведёт с объекта %q, а поверхность объявлена как %q: "+
					"служебная дверь на публичном объекте расширяет периметр тем же рычагом, "+
					"которым оператор выводит наружу публичные (запрет #6)", otherService(want), s.Reach)
			default:
				r.why = fmt.Sprintf("порта %s нет ни на одном объекте Service: процесс поднимает дверь, к которой чарт не ведёт", r.port)
			}
		}

		if r.via != "" {
			routed++
			lines = append(lines, fmt.Sprintf("  %-38s :%-5s %-16s → %s", s.SettingKey, r.port, s.Reach, r.via))
		} else {
			lines = append(lines, fmt.Sprintf("  %-38s :%-5s %-16s → МАРШРУТА НЕТ", s.SettingKey, r.port, s.Reach))
			findings = append(findings, fmt.Sprintf("%s (%s, :%s): %s", s.Name, s.SettingKey, r.port, r.why))
		}

		if !container[r.port] {
			findings = append(findings, fmt.Sprintf(
				"%s (%s): под не объявляет порта %s — маршрут может вести на дверь, которой под не называет",
				s.Name, s.SettingKey, r.port))
		}
	}

	sort.Strings(lines)
	t.Logf("ПЕРЕПИСЬ поверхностей чарта службы:\n%s\n"+
		"  прочитано файлов объявлений: %d · умолчаний адресов: %d · объектов Service: %d\n"+
		"  поверхностей ПОДНЯТО %d · С МАРШРУТОМ %d",
		strings.Join(lines, "\n"), roster.FilesRead, roster.DefaultsRead, len(svcTypes), raised, routed)

	require.NotZero(t, raised,
		"этим входом не поднято ни одной поверхности — «ноль находок» было бы неотличимо от «ноль прочитанного»")
	return raised, routed, findings
}

const (
	publicServiceName   = "kaname"
	internalServiceName = "kaname-internal"
)

// routeSourcesPresent — ПРЕДПОСЫЛКА гейта: маршруты вообще есть откуда читать.
//
// Отдельной функцией с возвращаемой ошибкой, а не проверкой внутри пробы:
// доказательство способности гейта упасть обязано звать ЕЁ ЖЕ. Рендер, в котором
// не нашлось ни объектов Service, ни объявления сбора, — это «нечем искать», и
// вердикт «поверхностей 0, все покрыты» был бы вакуумным зелёным ровно там, где
// гейт нужнее всего.
func routeSourcesPresent(svcPorts map[string]map[string]bool, scrape scrapeDecl) error {
	ports := 0
	for _, set := range svcPorts {
		ports += len(set)
	}
	if ports == 0 && !scrape.enabled {
		return fmt.Errorf("в рендере нет ни одного порта Service и нет объявления сбора: " +
			"читать маршруты неоткуда, и «ноль находок» было бы неотличимо от «ноль прочитанного»")
	}
	return nil
}

func otherService(name string) string {
	if name == publicServiceName {
		return internalServiceName
	}
	return publicServiceName
}

var addrPortRe = regexp.MustCompile(`:(\d+)$`)

func portOfAddr(addr string) string {
	if m := addrPortRe.FindStringSubmatch(addr); m != nil {
		return m[1]
	}
	return ""
}

// renderedConfigTree разбирает тело настроек рендера в дерево.
func renderedConfigTree(t *testing.T, rendered string) map[string]any {
	t.Helper()
	in := readRenderedInput(t, rendered)
	var tree map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(in.ConfigBody), &tree), "тело настроек рендера")
	return tree
}

// configString достаёт значение по точечному ключу конфигурации.
func configString(tree map[string]any, key string) string {
	cur := any(tree)
	for _, seg := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[seg]
		if !ok {
			return ""
		}
	}
	s, _ := cur.(string)
	return s
}

// renderedServicePorts — порты каждого объекта Service рендера.
func renderedServicePorts(t *testing.T, rendered string) (map[string]map[string]bool, map[string]string) {
	t.Helper()
	ports := map[string]map[string]bool{}
	types := map[string]string{}
	forEachDoc(t, rendered, func(doc map[string]any) {
		if k, _ := doc["kind"].(string); k != "Service" {
			return
		}
		meta, _ := doc["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		spec, _ := doc["spec"].(map[string]any)
		if tp, ok := spec["type"].(string); ok {
			types[name] = tp
		}
		set := map[string]bool{}
		list, _ := spec["ports"].([]any)
		for _, p := range list {
			pm, _ := p.(map[string]any)
			set[fmt.Sprintf("%v", pm["port"])] = true
		}
		ports[name] = set
	})
	return ports, types
}

// renderedContainerPorts — порты, которые объявляет под.
func renderedContainerPorts(t *testing.T, rendered string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	forEachDoc(t, rendered, func(doc map[string]any) {
		if k, _ := doc["kind"].(string); k != "Deployment" {
			return
		}
		spec, _ := doc["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		pspec, _ := tmpl["spec"].(map[string]any)
		conts, _ := pspec["containers"].([]any)
		for _, c := range conts {
			cm, _ := c.(map[string]any)
			list, _ := cm["ports"].([]any)
			for _, p := range list {
				pm, _ := p.(map[string]any)
				out[fmt.Sprintf("%v", pm["containerPort"])] = true
			}
		}
	})
	return out
}

type scrapeDecl struct {
	enabled bool
	port    string
	scheme  string
}

// renderedScrapeDeclared — объявление сбора шаблона пода.
func renderedScrapeDeclared(t *testing.T, rendered string) scrapeDecl {
	t.Helper()
	var out scrapeDecl
	forEachDoc(t, rendered, func(doc map[string]any) {
		if k, _ := doc["kind"].(string); k != "Deployment" {
			return
		}
		spec, _ := doc["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		meta, _ := tmpl["metadata"].(map[string]any)
		ann, _ := meta["annotations"].(map[string]any)
		if fmt.Sprintf("%v", ann["prometheus.io/scrape"]) == "true" {
			out.enabled = true
			out.port = fmt.Sprintf("%v", ann["prometheus.io/port"])
			out.scheme = fmt.Sprintf("%v", ann["prometheus.io/scheme"])
		}
	})
	return out
}

func forEachDoc(t *testing.T, rendered string, fn func(map[string]any)) {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	seen := 0
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc == nil {
			continue
		}
		seen++
		fn(doc)
	}
	require.NotZero(t, seen, "рендер не дал ни одного документа")
}
