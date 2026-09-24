// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_surface_test.go — ЕДИНСТВЕННОСТЬ ПОВЕРХНОСТИ ЦЕРЕМОНИИ держится
// гейтом по дереву (kaname#320; приёмка LINE-A-1, сценарий LINE-A-1-23).
//
// # Предмет
//
// «Эндпоинты церемонии монтируются на внешней поверхности выдачи и НИГДЕ
// больше». Держала это проба с ВЫПИСАННЫМ перечнем внутренних мультиплексоров
// и текстовым счётом имени константы по одному файлу корня: слушатель,
// заведённый после неё, в перечне отсутствовал, а монтаж, уехавший в
// конструктор пакета, в файл корня не попадал вовсе. Свойство держалось
// званием эталона, а не обходом (класс hard-gate-not-reference-title).
//
// Здесь перечня нет ни одного. Поверхности выводятся из объявлений
// `servicecontract.Surface`, мультиплексоры и их регистрации — прослеживанием
// значений по всему коду, линкуемому в бинарь службы, а «резолвится» решает
// НАСТОЯЩИЙ мультиплексор (`net/http` и шлюза), собранный из выведенных
// образцов. Устройство разбора, его границы и перечень форм — в
// `ceremony_surface.go`.
//
// # Что здесь, а что рядом
//
// Живой прогон и проба предпосылки — здесь. Падучесть доказывается
// инъекциями настоящим входом (копия живого корня с одной правкой) в
// `ceremony_surface_injection_test.go`.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/servicecontract"
	"golang.org/x/mod/modfile"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/treeroot"
	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// ceremonyRootDir — каталог композиционного корня ОТНОСИТЕЛЬНО корня модуля.
//
// Единственная выписанная координата гейта, и выписана она потому, что это
// ВХОД обхода, а не его итог: всё остальное выводится из того, что линкуется
// в этот бинарь.
const ceremonyRootDir = "cmd/kaname"

// Досягаемость в находке и в выведенной таблице пишется словом фундамента
// (servicecontract.SurfaceReach.String) — тем же, что несут журнал и
// tools/surfaceroster; своего написания у гейта нет.
var (
	reachExternalMark = "[" + servicecontract.ReachExternal.String() + "]"
	reachInternalMark = "[" + servicecontract.ReachClusterInternal.String() + "]"
)

// liveCeremonyCoordinates — координаты, которые судит живой прогон.
//
// Путь токен-эндпоинта берётся у ПРОИЗВОДИТЕЛЯ: он смонтирован, и он — якорь,
// по которому выводится поверхность выдачи. Эндпоинт авторизации и метаданные
// обнаружения ВЫПИСАНЫ: производителей у них в дереве нет (приёмка LINE-A-1,
// §9: «не начаты»). Это названная граница, и она истекает сама: появись
// постоянная с таким значением в бинаре — гейт покраснеет с требованием взять
// путь у неё.
func liveCeremonyCoordinates() []check.CeremonyCoordinate {
	return []check.CeremonyCoordinate{
		{Name: "токен-эндпоинт", Path: clienttokenhttp.TokenPath, Anchor: true},
		{Name: "эндпоинт авторизации", Path: "/iam/v1/authorize", Written: true},
		{Name: "метаданные обнаружения", Path: "/.well-known/oauth-authorization-server", Written: true},
	}
}

// liveUnresolvedLedger — листы путей регистрации, которые разбор НЕ сводит к
// значению на живом дереве, с МЕСТОМ регистрации. Точная ведомость, а не
// потолок: новый лист — находка, тот же лист на другом месте — находка,
// запись без листа на своём месте — находка.
func liveUnresolvedLedger() []check.UnresolvedPathEntry {
	return []check.UnresolvedPathEntry{{
		Leaf: "поле github.com/PRO-Robotech/kaname/internal/apps/kaname/config.TokenSigningConfig.KeySetPath " +
			"(заполняется декодером настройки)",
		Where: "github.com/PRO-Robotech/kaname/internal/handler/jwksproxyhttp.NewMux",
		// Граница, а не пропуск. Путь НАШЕЙ записи публикуемого набора ключей
		// объявляет оператор (`key-set-path`); регистрирует его петля записей
		// набора на поверхности ключей (jwksproxyhttp/binding.go). Страж
		// настройки проверяет лишь непустой сегмент — путь, совпавший с
		// координатой поверхности выдачи, разбор кода увидеть не может: его
		// значение рождается в профиле развёртывания.
		//
		// Предикат снятия: страж старта отвергает путь набора ключей, равный
		// координате поверхности выдачи, — тогда запись заменяется ссылкой на
		// него; либо путь перестаёт быть ручкой и становится постоянной.
		Why: "путь набора ключей задаёт профиль развёртывания; совпадение с координатой разбором не судится",
	}}
}

// ceremonyModuleRoot — корень модуля по маркеру go.mod.
func ceremonyModuleRoot(t *testing.T) string {
	t.Helper()
	root, err := treeroot.ModuleRootFrom(".")
	if err != nil {
		t.Fatalf("корень модуля: %v", err)
	}
	return root
}

// ceremonyModulePath — путь модуля из go.mod.
func ceremonyModulePath(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("go.mod: %v", err)
	}
	path := modfile.ModulePath(data)
	if path == "" {
		t.Fatalf("go.mod %s не называет модуль", root)
	}
	return path
}

// judgeLiveCeremony — прогон гейта по живому дереву.
func judgeLiveCeremony(t *testing.T) check.CeremonySurfaceReport {
	t.Helper()
	return judgeLiveCeremonyWith(t, liveUnresolvedLedger())
}

// judgeLiveCeremonyWith — прогон по живому дереву с данной ведомостью листов.
func judgeLiveCeremonyWith(t *testing.T, ledger []check.UnresolvedPathEntry) check.CeremonySurfaceReport {
	t.Helper()
	root := ceremonyModuleRoot(t)
	report, err := check.JudgeCeremonySurfaces(t.Context(), check.CeremonySurfaceSpec{
		ModuleRoot:  root,
		RootPackage: ceremonyModulePath(t, root) + "/" + ceremonyRootDir,
		Unresolved:  ledger,
	}, liveCeremonyCoordinates())
	if err != nil {
		t.Fatalf("гейт НЕ ИСПОЛНИЛСЯ — это не зелёное и не находка: %v", err)
	}
	return report
}

// TestCeremonySurfaceIsSingularAcrossTheCompositionRoot — живой прогон:
// каждая координата церемонии резолвится ровно на одной поверхности, и это
// поверхность выдачи.
func TestCeremonySurfaceIsSingularAcrossTheCompositionRoot(t *testing.T) {
	report := judgeLiveCeremony(t)
	t.Logf("%s", report.Census.Summary())
	for _, c := range report.Coordinates {
		t.Logf("%s", c.Summary())
	}
	if len(report.Findings) > 0 {
		t.Errorf("находок %d:\n%s", len(report.Findings), strings.Join(report.Findings, "\n"))
	}
}

// TestCeremonySurfaceGatePremiseHolds — проба ПРЕДПОСЫЛКИ: корень разобран,
// поверхности выведены, и выведено столько, сколько поднимается.
//
// Без неё «находок ноль» неотличимо от «ничего не прочитано»: обход, не
// нашедший ни одной поверхности, зелен по той же причине, что исправный.
func TestCeremonySurfaceGatePremiseHolds(t *testing.T) {
	report := judgeLiveCeremony(t)
	c := report.Census
	t.Logf("%s", c.Summary())
	for _, p := range []struct {
		what string
		got  int
	}{
		{"разобрано файлов", c.Files},
		{"файлов корня", c.RootFiles},
		{"объявлений поверхности", c.SurfaceDecls},
		{"элементов среза подъёма", c.RaisedSurfaces},
		{"регистраций на мультиплексорах net/http", c.HTTPRegistrations},
		{"регистраций на мультиплексорах шлюза", c.GatewayRegistrations},
		{"стоков HTTP-сервера (подъём объявленных поверхностей)", c.Sinks},
		{"конечных точек координат (суд о монтаже обработчика)", c.CoordinateEndpoints},
		{"конечных точек поверхностей (с чем сверяется обработчик)", c.SurfaceEndpoints},
	} {
		if p.got == 0 {
			t.Errorf("%s: 0 — разбор ослеп, а не дерево опустело: корень без поверхностей не поднимается", p.what)
		}
	}
	if c.SurfaceDecls != c.RaisedSurfaces {
		t.Errorf("объявлено поверхностей %d, поднимается %d — судится не то, что поднимается", c.SurfaceDecls, c.RaisedSurfaces)
	}
	if len(report.Surfaces) != c.SurfaceDecls {
		t.Errorf("обойдено поверхностей %d при объявленных %d", len(report.Surfaces), c.SurfaceDecls)
	}
	for _, s := range report.Surfaces {
		if s.Roots == 0 {
			t.Errorf("поверхность «%s»: обработчик не прослежен ни до одного значения", s.Name)
		}
	}

	// Два производителя одного перечня сверяются МЕЖДУ СОБОЙ: перечень
	// поверхностей для чарта и документа установки (tools/surfaceroster)
	// выводится своим разбором. Разошлись — один из двух ослеп, и молча.
	roster, err := surfaceroster.Read(ceremonyModuleRoot(t))
	if err != nil {
		t.Fatalf("перечень поверхностей tools/surfaceroster: %v", err)
	}
	want := map[string]string{}
	for _, s := range roster.Surfaces {
		if !s.GRPC {
			want[s.Name] = s.Reach
		}
	}
	got := map[string]string{}
	for _, s := range report.Surfaces {
		got[s.Name] = s.Reach
	}
	if len(want) == 0 {
		t.Fatalf("tools/surfaceroster не назвал ни одной HTTP-поверхности — сверять не с чем")
	}
	for name, reach := range want {
		if got[name] != reach {
			t.Errorf("поверхность «%s» [%s] есть в tools/surfaceroster, у гейта — [%s]", name, reach, got[name])
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("поверхность «%s» выведена гейтом, а tools/surfaceroster её не знает", name)
		}
	}
}

// TestCeremonySurfaceGateSeesTheLiveTwins — законные близнецы живого дерева
// ВИДНЫ гейту и потому молчат по существу, а не по слепоте.
//
// Молчание гейта о близнеце, которого он не видел, неотличимо от молчания о
// близнеце, которого он рассудил. Поэтому здесь утверждается, что каждый
// близнец ПОПАЛ в выведенную таблицу маршрутов.
func TestCeremonySurfaceGateSeesTheLiveTwins(t *testing.T) {
	report := judgeLiveCeremony(t)

	coords := map[string]check.CoordinateVerdict{}
	for _, c := range report.Coordinates {
		coords[c.Name] = c
	}

	// Т2: живой положительный контроль — токен-эндпоинт на одной поверхности,
	// и она внешняя.
	token := coords["токен-эндпоинт"]
	if len(token.Surfaces) != 1 {
		t.Fatalf("токен-эндпоинт резолвится на %d поверхностях, ожидалась одна: %s", len(token.Surfaces), token.Summary())
	}
	if token.Surfaces[0].Reach != servicecontract.ReachExternal.String() {
		t.Errorf("токен-эндпоинт резолвится на поверхности с досягаемостью %s", token.Surfaces[0].Reach)
	}
	// Обработчик якоря прослежен до значения: иначе суд о монтаже того же
	// эндпоинта под чужим путём на другой поверхности молчал бы по слепоте.
	if len(token.Endpoints) == 0 {
		t.Errorf("обработчик токен-эндпоинта не прослежен ни до одного значения — монтаж под чужим путём "+
			"не судится: %s", token.Summary())
	}
	t.Logf("конечные точки токен-эндпоинта: %s", strings.Join(token.Endpoints, "; "))

	// Т14: у эндпоинта авторизации и обнаружения производителя нет — это
	// отдельная категория переписи, и в положительный контроль она не идёт.
	for _, name := range []string{"эндпоинт авторизации", "метаданные обнаружения"} {
		c := coords[name]
		if len(c.Surfaces) != 0 || len(c.Producers) != 0 {
			t.Errorf("%s: поверхностей %d, производителей %d — на этом дереве ожидалось 0 и 0", name, len(c.Surfaces), len(c.Producers))
		}
	}
	if report.Census.WithoutProducer != 2 {
		t.Errorf("координат без производителя %d, ожидалось 2", report.Census.WithoutProducer)
	}
	if report.Census.PositiveControls != 1 {
		t.Errorf("положительных контролей %d, ожидался 1 (токен-эндпоинт)", report.Census.PositiveControls)
	}

	byReach := map[string][]check.SurfaceRoutes{}
	for _, s := range report.Surfaces {
		byReach[s.Reach] = append(byReach[s.Reach], s)
	}

	// Т4: правила шлюза `/iam/v1/authorize:{…}` стоят на ОБОИХ REST-фронтах.
	// Близнец по префиксу: образец с глаголом координату без глагола не берёт.
	var gatewayAuthorize int
	for _, s := range report.Surfaces {
		for _, p := range s.Patterns {
			if strings.Contains(p, "/iam/v1/authorize:") {
				gatewayAuthorize++
				break
			}
		}
	}
	if gatewayAuthorize != 2 {
		t.Errorf("правила шлюза /iam/v1/authorize:* видны на %d поверхностях, ожидалось 2 (оба REST-фронта)", gatewayAuthorize)
	}

	// Чтения пути запроса живого дерева (журнал) видны распознавателю ручной
	// маршрутизации и рассужены им: чтений больше нуля, решений маршрута — 0.
	if report.Census.URLPathReads == 0 {
		t.Errorf("чтений пути запроса 0 — распознаватель ручной маршрутизации ослеп: живое дерево пишет путь в журнал")
	}
	if len(report.Census.ManualRouting) != 0 {
		t.Errorf("живое дерево решает маршрут по пути запроса: %v", report.Census.ManualRouting)
	}
	t.Logf("чтений пути запроса %d, решений маршрута по нему %d", report.Census.URLPathReads, len(report.Census.ManualRouting))

	// Т6 и Т7: полоса входа и набор ключей видны своими маршрутами.
	for _, want := range []string{"/iam/v1/auth/login", "/.well-known/jwks.json", "/iam/token", "/metrics"} {
		var seen bool
		for _, s := range report.Surfaces {
			for _, p := range s.Patterns {
				if strings.HasSuffix(p, want) {
					seen = true
				}
			}
		}
		if !seen {
			t.Errorf("маршрут %s не попал ни в одну выведенную таблицу — близнец молчит по слепоте", want)
		}
	}
}

// TestCeremonySurfaceLedgerIsExactByPlace — L1: ведомость листов пути точна
// по МЕСТУ регистрации, а не по листу. Запись без предмета — находка; лист на
// месте, которого запись не называет, — находка, даже если сам лист объявлен.
func TestCeremonySurfaceLedgerIsExactByPlace(t *testing.T) {
	live := liveUnresolvedLedger()

	t.Run("entry_without_subject", func(t *testing.T) {
		ledger := append(liveUnresolvedLedger(), check.UnresolvedPathEntry{
			Leaf: "поле пробы (заполняется декодером настройки)", Where: live[0].Where, Why: "проба",
		})
		report := judgeLiveCeremonyWith(t, ledger)
		requireFinding(t, report, "без предмета", "поле пробы")
	})

	t.Run("declared_leaf_at_an_undeclared_place", func(t *testing.T) {
		report := judgeLiveCeremonyWith(t, []check.UnresolvedPathEntry{{
			Leaf: live[0].Leaf, Where: "github.com/PRO-Robotech/kaname/cmd/kaname.ceremonyNowhere", Why: "проба",
		}})
		requireFinding(t, report, "без предмета", "ceremonyNowhere")
		requireFinding(t, report, "не сводится к значению", "KeySetPath", "jwksproxyhttp/binding.go:")
	})

	t.Run("exact_ledger_is_silent", func(t *testing.T) {
		report := judgeLiveCeremonyWith(t, liveUnresolvedLedger())
		if len(report.Findings) > 0 {
			t.Fatalf("точная ведомость дала находки:\n%s", strings.Join(report.Findings, "\n"))
		}
	})
}
