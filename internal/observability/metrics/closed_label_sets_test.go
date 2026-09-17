// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// closed_label_sets_test.go — ПРОБА ПАКЕТА: у семейства с закрытым, перечислимым
// при сборке набором меток клетки заведены нулём при регистрации (kacho#2500).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Вектор без детей не отдаёт на провод НИЧЕГО. Поэтому у незасеянного семейства
// «механизм не провязан» и «механизм провязан и ни разу не сработал» дают одну и
// ту же пустоту — то есть ровно то различение, ради которого ось наблюдаемости и
// заведена, у него отсутствует.
//
// Норма была объявлена в пакете трижды прозой и исполнена четырежды кодом. Проза
// владельца не имеет: она стареет молча вместе с тем, из чего выведена, и один
// из не-заводивших прямо утверждал, что различение достигнуто.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБА ПАКЕТА, А НЕ ДЕВЯТЬ ПОФАЙЛОВЫХ
//
// Пофайловая проба утверждает о СВОЁМ семействе и молчит о соседнем. Девять
// таких проб держали свойство у девяти семейств и ничего не говорили о десятом —
// а предмет здесь свойство ПАКЕТА: «ни одного незасеянного закрытого набора».
// Десятое семейство заводится соседним изменением, и пофайловый перечень о нём
// не узнает никогда.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ ПОЛОВИНЫ, И ОНИ ПРОВЕРЯЮТ ДРУГ ДРУГА
//
//	ПЕРЕПИСЬ  — разбор дерева пакета: каждое объявление `prometheus.New*Vec` даёт
//	            имя семейства. Она и есть «объём осмотренного»: без неё «ноль
//	            находок» неотличимо от «ноль прочитанного».
//	ПОВЕДЕНИЕ — каждое закрытое семейство строится на СВЕЖЕМ реестре и
//	            собирается: рядов обязано быть не меньше объявленного числа
//	            клеток. Судится провод, а не форма записи в исходнике.
//
// Семейство переписи, не названное НИ таблицей, НИ ведомостью, — находка
// (слепая зона). Запись таблицы или ведомости, которой в переписи нет, — тоже
// находка: послабление и утверждение обязаны истекать вместе со своим предметом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
// Проба НЕ утверждает, что объявленный здесь набор клеток совпадает с набором,
// который производят вызывающие: у части наборов константы производителя
// неэкспортируемы и лежат в слое use-case, куда адаптеру величин ходить незачем.
// Расхождение такого рода — другой класс («полоса без производителя»), и у полос
// решения о доступе его держит сосед `TestEveryDeclaredLaneHasAProducer`.
//
// Проба НЕ судит коллекторы (`prometheus.Collector` со своим `Collect`): они
// отдают ВСЕ клетки на каждом скрейпе by construction, и заводить им нечего.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// closedLabelSet — семейство, чей набор клеток ЗАКРЫТ и перечислим при сборке.
type closedLabelSet struct {
	// Cells — сколько рядов обязано быть на проводе СРАЗУ после регистрации.
	Cells int
	// Build повторяет то, что делает композиционный корень: регистрирует
	// семейство в переданном реестре.
	Build func(*Registry)
	// Why — чем клетка отвечает оператору. Одна строка, не пересказ шапки.
	Why string
}

// openLabelSet — прощённое семейство: набор меток при сборке НЕ перечислим.
type openLabelSet struct {
	// Reason — почему перечислить нечем. Проверяется человеком, не машиной.
	Reason string

	// Поля `ProducerMethod` здесь больше НЕТ — снято вместе со своим
	// единственным предметом (#2638).
	//
	// Оно делало прощение самоистекающим у семейства, которому прощали
	// «засевать нечем, производителя нет вовсе»: появился вызывающий — набор
	// стал перечислим у него. Такое семейство в пакете было ровно одно, и оно
	// снято целиком; у остальных записей набор открыт по другой причине —
	// метку приносит вызывающий, и вызывающий у них есть.
	//
	// Класс, ради которого поле стояло, держится теперь ШИРЕ: гейт
	// `TestIAM2638_EveryDeclaredMetricProducerHasACaller` судит ВСЮ популяцию
	// производителей фасада, а не одну объявленную запись. Понадобится простить
	// семейство, у которого производителя нет, — сперва спроси, зачем оно
	// зарегистрировано.
}

// closedLabelSetFamilies — семейства с закрытым набором клеток.
//
// Ключ — ИМЯ СЕМЕЙСТВА на проводе, а не имя конструктора: конструктор
// регистрирует по нескольку семейств, и запись на конструктор скрыла бы
// незасеянного соседа под засеянным.
var closedLabelSetFamilies = map[string]closedLabelSet{
	Namespace + "_authz_check_duration_seconds": {
		Cells: len(DeclaredAuthzLanes()) * 2, // rpc × allowed
		Build: func(r *Registry) {},          // заводится самим NewRegistry
		Why:   "полоса, которой никто не пользуется, обязана быть видна нулём, а не отсутствовать",
	},
	Namespace + "_authz_check_decisions_total": {
		Cells: len(DeclaredAuthzLanes()) * len(AuthzDecisions), // rpc × decision
		Build: func(r *Registry) {},
		Why:   "«отказов не было» обязано быть отличимо от «полосу ни разу не спрашивали»",
	},
	Namespace + "_catalog_snapshot_refreshes_total": {
		Cells: len(CatalogSnapshotOutcomes),
		Build: func(r *Registry) { r.NewCatalogSnapshotRecorder() },
		Why:   "мёртвое обновление снимка снаружи неотличимо от исправного: снимок продолжает отвечать прежним множеством",
	},
	Namespace + "_provider_compensations_emitted_total": {
		Cells: len(CompensationOrigins) * len(CompensationEmitOutcomes),
		Build: func(r *Registry) { r.NewCompensationRecorder() },
		Why:   "«ноль компенсаций» — и здоровое облако, и непровязанный механизм",
	},
	Namespace + "_provider_compensations_applied_total": {
		Cells: len(CompensationOrigins),
		Build: func(r *Registry) { r.NewCompensationRecorder() },
		Why:   "расхождение записанных и исполненных читается только когда обе серии существуют",
	},
	// ── ПОЛОСА ВХОДА ПАРОЛЕМ (Ф3, kacho#1269) ────────────────────────────────
	// Один конструктор, семь семейств: запись на каждое, иначе незасеянный сосед
	// прятался бы под засеянным. Словари — у производителей событий.
	LoginOutcomesMetric: {
		Cells: len(humansession.LoginOutcomes()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "вызывающий видит ОДИН отказ; причина — только здесь, и «ноль по причине» видно до первого события",
	},
	PasswordVerificationOutcomesMetric: {
		Cells: len(passwordverify.OutcomeNames()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "исход «у нас негодные данные» обязан быть виден нулём: он не отказ человеку, а находка о хранилище",
	},
	HumanSessionNoSessionMetric: {
		Cells: len(humansession.NoSessionReasons()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "«сессии нет» по четырём причинам — один ответ краю; причина считается только здесь",
	},
	LoginFormRefusalsMetric: {
		Cells: len(humansession.FormRefusals()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "отказ формы, которого не было ни разу, обязан быть отличим от формы, которую никто не судил",
	},
	LoginRateLimitRefusalsMetric: {
		Cells: 2, // address × source
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "предел по каждой оси виден нулём: ось, о которой никто не спрашивал, не отсутствует",
	},
	PasswordBreachCheckMetric: {
		Cells: len(humansession.BreachCheckOutcomes()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "«проверка не состоялась ни разу» видно только когда клетка есть с нулём (Ф3-34)",
	},
	PasswordMaterialRewriteMetric: {
		Cells: len(humansession.RewriteOutcomes()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "переписывание материала, которое не случилось ни разу, обязано быть отличимо от непровязанного",
	},
	// ── ВТОРОЙ ФАКТОР (Ф12, kacho#1281) ─────────────────────────────────────
	SecondFactorPresentationsMetric: {
		Cells: len(humansession.PresentationCells()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "«материал не открылся» — находка о ключнице, а не отказ человеку: ноль по ней обязан быть виден до первого события",
	},
	SecondFactorRefusalsMetric: {
		Cells: len(humansession.SecondFactorRefusals()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "отказ по состоянию попыткой не считается и в счёт подбора не идёт — виден только здесь",
	},
	SecondFactorEventsMetric: {
		Cells: len(humansession.SecondFactorEvents()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "ноль заведений за всю жизнь и непровязанный глагол выглядят одинаково без клетки",
	},
	RegistrationOutcomesMetric: {
		Cells: len(registration.Lanes) * len(registration.Outcomes()), // полоса × исход
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "вызывающий видит ОДИН отказ регистрации (Ф4 Р3); занятость и потолок темпа различимы только клеткой, и клетка обязана быть с нулём до первого события",
	},
	// ── ВОССТАНОВЛЕНИЕ ДОСТУПА (Ф5, kacho#1271) — тот же конструктор ─────────
	RecoveryRequestOutcomesMetric: {
		Cells: len(humansession.RecoveryRequestOutcomes()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "ответ на запрос кода один при любом исходе (Ф5-02); «ноль по причине» видно до первого запроса",
	},
	RecoveryCompletionOutcomesMetric: {
		Cells: len(humansession.RecoveryCompletionOutcomes()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "отказ на предъявление один (Ф1-59); заблокированная, истёкший и чужой код различимы только здесь",
	},
	// ── ОГИБАЮЩАЯ ПО ПОТОЛКУ (Ф3-31, kaname#188) — тот же конструктор ──────────
	LoginTimingCalibrationsMetric: {
		Cells: len(passwordverify.EnvelopeTriggers()),
		Build: func(r *Registry) { r.LoginLaneRecorder() },
		Why:   "калибровка по чтению означает значение, положенное мимо этого процесса; «ни разу» обязано быть видно нулём, а не отсутствием",
	},
	Namespace + "_invite_activations_total": {
		Cells: len(InviteActivationOutcomes),
		Build: func(r *Registry) { r.NewInviteActivationRecorder() },
		Why:   "путь первого входа, умерший целиком, выглядел бы здоровее всех",
	},
	Namespace + "_invite_mail_intents_total": {
		Cells: len(InviteMailIntentOutcomes),
		Build: func(r *Registry) { r.NewInviteMailIntentRecorder() },
		Why:   "ограничение частоты для вызывающего невидимо by construction (Р9); незасеянная клетка rate_limited означала бы «сюда никто не приходил» там, где письма молча не уходят",
	},
	Namespace + "_module_catalog_applies_total": {
		Cells: len(ModuleCatalogApplyOutcomes),
		Build: func(r *Registry) { r.NewModuleCatalogRecorder() },
		Why:   "знаменатель: без него ноль соседей означает и «каталог не менялся», и «применитель не ходил»",
	},
	Namespace + "_module_catalog_retired_rows_total": {
		Cells: len(ModuleCatalogRetiredKinds),
		Build: func(r *Registry) { r.NewModuleCatalogRecorder() },
		Why:   "вид снятой строки обязан существовать нулём, иначе «ресурсов не снимали» невидимо",
	},
	Namespace + "_module_catalog_resettled_projections_total": {
		Cells: len(ModuleCatalogResettledPopulations),
		Build: func(r *Registry) { r.NewModuleCatalogRecorder() },
		Why:   "популяции — разные события, и сумма их не различает; пустая серия не различает и подавно",
	},
	Namespace + "_registry_token_credential_kind_total": {
		Cells: len(RegistryTokenCredentialKindOutcomes),
		Build: func(r *Registry) { r.NewRegistryTokenCredentialKindRecorder() },
		Why:   "клетка окна перехода — ПРЕДИКАТ его закрытия: её отсутствие читается как «переведены все»",
	},
	Namespace + "_role_rule_ref_reseeds_total": {
		Cells: len(RuleRefReseedOutcomes),
		Build: func(r *Registry) { r.NewRuleRefReseedRecorder() },
		Why:   "досев, не запускавшийся ни разу, обязан быть отличим от досева без отказов",
	},
	Namespace + "_role_verb_reseeds_total": {
		Cells: len(RoleVerbReseedOutcomes),
		Build: func(r *Registry) { r.NewRoleVerbReseedRecorder() },
		Why:   "то же, что у соседа: знаменатель обязан существовать",
	},
	Namespace + "_bootstrap_admin_attempts_total": {
		Cells: len(seed.BootstrapOutcomes),
		Build: func(r *Registry) { r.NewBootstrapAdminRecorder() },
		Why:   "согласователь встроенного администратора ходит редко — молчание у него штатно",
	},
	ProviderRoadOutcomesMetric: {
		Cells: len(clients.ProviderRoads) * len(clients.ProviderRoadOutcomes),
		Build: func(r *Registry) { r.NewProviderRoadRecorder() },
		Why:   "дорога, по которой не ходили, и дорога, которую не провязали, обязаны различаться",
	},
	InviteMailOutcomesMetric: {
		Cells: len(clients.InviteMailOutcomes),
		Build: func(r *Registry) { r.NewInviteMailRecorder() },
		Why:   "эталон формы: «сюда никто не приходил» отличимо от «отказов не было»",
	},
	Namespace + "_register_postcommit_steps_total": {
		Cells: len(RegisterPostCommitSteps) * len(RegisterPostCommitOutcomes),
		Build: func(r *Registry) { r.NewRegisterPostCommitRecorder() },
		Why:   "шаг после коммита, который не исполняется, выглядел бы как шаг без отказов",
	},
	AuthnHookRequestsMetric: {
		Cells: 2 * 2, // маршрутов × исходов, набор приходит доводом от корня
		Build: func(r *Registry) {
			r.AuthnHooksRecorder([]string{"login", "registration"}, []string{"ok", "error"})
		},
		Why: "полоса хуков поставщика личности: непровязанный маршрут обязан быть виден нулём",
	},
	ReadinessChecksMetric: {
		Cells: 1 * len(ReadinessOutcomes), // одна названная зависимость × исходы
		Build: func(r *Registry) { r.ReadinessRecorder([]string{"database"}) },
		Why:   "все ряды в нуле — ТРЕТЬЕ состояние: готовность не оценивали ни разу",
	},
	ExpiredCredentialReclaimPassesMetric: {
		Cells: 2,
		Build: func(r *Registry) { r.ExpiredCredentialSweepRecorder([]string{"ok", "error"}) },
		Why:   "уборщик по сроку, который не поднялся, обязан быть отличим от уборщика без отказов",
	},
}

// openLabelSetFamilies — ведомость семейств, чей набор при сборке НЕ перечислим.
//
// Запись, которой больше нечего прощать, — находка: послабление обязано истекать
// само, иначе его унаследует следующая слепая зона.
var openLabelSetFamilies = map[string]openLabelSet{
	LoginTimingClassCostMetric: {
		Reason: "метки `format` и `params` — класс стоимости хранимого значения; перечень классов " +
			"принадлежит ПОПУЛЯЦИИ хранилища (перепись при старте) и классу ручки, а не сборке: ряд " +
			"заводится калибровкой класса, и «класса нет в популяции» выражается его отсутствием.",
	},
	Namespace + "_list_rows_scanned": {
		Reason: "метка `resource` — имя ресурса списочной выдачи; перечень принадлежит " +
			"каталогу модулей и растёт вместе с ним, а не объявляется здесь.",
	},
	Namespace + "_list_permission_checks": {
		Reason: "то же, что у соседа: `resource` приносит вызывающий.",
	},
	Namespace + "_lro_terminal_write_retries_total": {
		Reason: "метка `op_type` — вид длительной операции; перечень принадлежит " +
			"фундаменту (`operations`), а не этому адаптеру.",
	},
	Namespace + "_lro_terminal_write_failures_total": {
		Reason: "то же, что у соседа: `op_type` приносит фундамент.",
	},
	Namespace + "_lro_orphans_recovered_total": {
		Reason: "исход возврата осиротевшей операции приходит из фундамента " +
			"(`operations.Recorder`), и его набор объявлен там, а не здесь.",
	},
	Namespace + "_outbox_backlog_depth": {
		Reason: outboxTableIsNotEnumerableHere,
	},
	Namespace + "_outbox_oldest_pending_age_seconds": {
		Reason: outboxTableIsNotEnumerableHere,
	},
	Namespace + "_outbox_poisoned_count": {
		Reason: outboxTableIsNotEnumerableHere,
	},
	Namespace + "_outbox_backlog_depth_by_direction": {
		Reason: outboxTableIsNotEnumerableHere,
	},
	Namespace + "_outbox_oldest_pending_age_by_direction_seconds": {
		Reason: outboxTableIsNotEnumerableHere,
	},
	Namespace + "_outbox_delivered_total": {
		Reason: outboxTableIsNotEnumerableHere,
	},
	Namespace + "_outbox_scans_total": {
		Reason: outboxTableIsNotEnumerableHere,
	},
	Namespace + "_outbox_scan_failures_total": {
		Reason: outboxTableIsNotEnumerableHere,
	},
}

// outboxTableIsNotEnumerableHere — общая причина восьми семейств состояния
// очередей: метка `table` называет очередь, а перечень очередей объявляет
// композиционный корень при провязке сканеров и там же заводит ряды нулём.
const outboxTableIsNotEnumerableHere = "метка `table` называет очередь; перечень очередей " +
	"объявляет композиционный корень при провязке сканера и ТАМ ЖЕ заводит ряды нулём " +
	"(`ObserveScan`). Выписать его здесь значило бы завести второе место об одном предмете."

// vectorSite — объявление вектора в исходнике пакета.
type vectorSite struct {
	File   string
	Line   int
	Family string
	Ctor   string // NewCounterVec | NewGaugeVec | NewHistogramVec | NewSummaryVec
}

// closedSetCensus — объём осмотренного; печатается ВСЕГДА.
type closedSetCensus struct {
	Files      int
	Parsed     int
	Vectors    int
	Closed     int
	Open       int
	Unnamed    int // объявлений, чьё имя семейства не удалось разрешить
	Findings   int
	StaleTable int
	StaleOpen  int
}

func (c closedSetCensus) Summary() string {
	return fmt.Sprintf(
		"файлов пакета %d · разобрано %d · объявлений вектора %d · из них закрытых %d · "+
			"открытых %d · с неразрешённым именем %d · находок %d · записей таблицы без "+
			"предмета %d · записей ведомости без предмета %d",
		c.Files, c.Parsed, c.Vectors, c.Closed, c.Open, c.Unnamed,
		c.Findings, c.StaleTable, c.StaleOpen)
}

var vectorCtors = map[string]bool{
	"NewCounterVec":   true,
	"NewGaugeVec":     true,
	"NewHistogramVec": true,
	"NewSummaryVec":   true,
}

// scanVectorSites разбирает перечень файлов и возвращает объявления векторов.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт каталог пакета, а инъекция
// подаёт синтетический — доказательство, требующее испортить рабочую копию, в
// конвейере не исполняется никогда.
func scanVectorSites(files []string) (sites []vectorSite, c closedSetCensus, err error) {
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		c.Files++
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Parsed++
		consts := packageStringConsts(file)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !vectorCtors[sel.Sel.Name] {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "prometheus" {
				return true
			}
			c.Vectors++
			family := ""
			if len(call.Args) > 0 {
				family = familyNameOf(call.Args[0], consts)
			}
			sites = append(sites, vectorSite{
				File:   filepath.Base(path),
				Line:   fset.Position(call.Pos()).Line,
				Family: family,
				Ctor:   sel.Sel.Name,
			})
			return true
		})
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, c, nil
}

// familyNameOf разрешает поле `Name:` составного литерала опций в имя семейства.
//
// Форм ДВЕ, и обе законны в этом пакете: `Namespace + "_литерал"` и именованная
// константа пакета. Третьей формы гейт не знает и о ней ГОВОРИТ — имя остаётся
// пустым, и такое объявление попадает в перепись «с неразрешённым именем», а не
// молча исчезает из наблюдения.
func familyNameOf(arg ast.Expr, consts map[string]string) string {
	lit, ok := arg.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Name" {
			continue
		}
		return resolveStringExpr(kv.Value, consts)
	}
	return ""
}

// resolveStringExpr складывает выражение имени из строковых литералов и
// известных констант пакета. Неизвестная часть делает результат пустым.
func resolveStringExpr(e ast.Expr, consts map[string]string) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return ""
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return ""
		}
		return s
	case *ast.Ident:
		if s, ok := consts[v.Name]; ok {
			return s
		}
		return ""
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return ""
		}
		left := resolveStringExpr(v.X, consts)
		right := resolveStringExpr(v.Y, consts)
		if left == "" || right == "" {
			return ""
		}
		return left + right
	}
	return ""
}

// packageStringConsts собирает строковые константы уровня файла, включая
// объявленные через `Namespace + "…"`.
func packageStringConsts(file *ast.File) map[string]string {
	out := map[string]string{"Namespace": Namespace}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if s := resolveStringExpr(vs.Values[i], out); s != "" {
					out[name.Name] = s
				}
			}
		}
	}
	return out
}

// TestIAM2500_EveryClosedLabelSetSeedsItsCellsAtRegistration — гейт задачи #2500.
func TestIAM2500_EveryClosedLabelSetSeedsItsCellsAtRegistration(t *testing.T) {
	files, err := packageGoFiles(".")
	if err != nil {
		t.Fatalf("перечень файлов пакета: %v", err)
	}
	sites, census, err := scanVectorSites(files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	findings, staleTable, staleOpen := adjudicateLabelSets(sites, &census)
	defer func() { t.Logf("%s", census.Summary()) }()

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла пакета величин — вердикт " +
			"беспредметен: «ноль находок» неотличимо от «ноль прочитанного»")
	}
	if census.Vectors == 0 {
		t.Fatalf("в пакете не найдено НИ ОДНОГО объявления `prometheus.New*Vec` "+
			"(разобрано %d файлов) — это отказ РАЗБОРА, а не пакет без векторов",
			census.Parsed)
	}
	if census.Closed == 0 {
		t.Fatalf("ни одно объявление не опознано как закрытый набор (векторов %d) — "+
			"распознаватель имён семейств мёртв, и тогда «закрыт/открыт» он делит вслепую",
			census.Vectors)
	}

	for _, s := range findings {
		t.Errorf("%s:%d — семейство %q объявлено вектором `%s`, но не названо НИ таблицей "+
			"закрытых наборов, НИ ведомостью открытых. Это слепая зона: проба о нём не "+
			"утверждает ничего, и незасеянный закрытый набор проехал бы молча. Впиши его "+
			"в `closedLabelSetFamilies` с числом клеток либо в `openLabelSetFamilies` с "+
			"причиной, по которой набор при сборке не перечислим.",
			s.File, s.Line, s.Family, s.Ctor)
	}
	for _, name := range staleTable {
		t.Errorf("таблица `closedLabelSetFamilies`: семейства %q в пакете БОЛЬШЕ НЕТ — "+
			"утверждение пережило свой предмет. Снимите запись ВМЕСТЕ с семейством.", name)
	}
	for _, name := range staleOpen {
		t.Errorf("ведомость `openLabelSetFamilies`: записи %q больше нечего прощать — "+
			"послабление пережило свой предмет и досталось бы следующему дефекту даром. "+
			"Снимите запись ВМЕСТЕ с семейством.", name)
	}

	for _, name := range sortedKeys(closedLabelSetFamilies) {
		want := closedLabelSetFamilies[name]
		got := rowsAfterRegistration(t, name, want.Build)
		if got >= want.Cells {
			continue
		}
		t.Errorf("семейство %q отдаёт %d рядов сразу после регистрации, а клеток "+
			"закрытого набора %d. Вектор без детей не отдаёт на провод НИЧЕГО: «механизм "+
			"не провязан» и «механизм провязан и ни разу не сработал» становятся одной и "+
			"той же пустотой. Заведи клетки нулём в конструкторе (`WithLabelValues(…)` по "+
			"всему набору) — зачем: %s.",
			name, got, want.Cells, want.Why)
	}
}

// adjudicateLabelSets разводит объявления на прощённые, закрытые и находки.
func adjudicateLabelSets(sites []vectorSite, c *closedSetCensus) (findings []vectorSite, staleTable, staleOpen []string) {
	seen := map[string]bool{}
	for _, s := range sites {
		if s.Family == "" {
			c.Unnamed++
			findings = append(findings, s)
			continue
		}
		seen[s.Family] = true
		switch {
		case hasClosedEntry(s.Family):
			c.Closed++
		case hasOpenEntry(s.Family):
			c.Open++
		default:
			findings = append(findings, s)
		}
	}
	for _, name := range sortedKeys(closedLabelSetFamilies) {
		if !seen[name] {
			staleTable = append(staleTable, name)
		}
	}
	for _, name := range sortedKeys(openLabelSetFamilies) {
		if !seen[name] {
			staleOpen = append(staleOpen, name)
		}
	}
	c.Findings = len(findings)
	c.StaleTable = len(staleTable)
	c.StaleOpen = len(staleOpen)
	return findings, staleTable, staleOpen
}

func hasClosedEntry(name string) bool { _, ok := closedLabelSetFamilies[name]; return ok }
func hasOpenEntry(name string) bool   { _, ok := openLabelSetFamilies[name]; return ok }

// rowsAfterRegistration строит семейство на СВЕЖЕМ реестре и считает ряды,
// которые оно отдаёт на провод сразу после регистрации.
func rowsAfterRegistration(t *testing.T, family string, build func(*Registry)) int {
	t.Helper()
	r := NewRegistry()
	build(r)
	families, err := r.reg.Gather()
	if err != nil {
		t.Fatalf("собрать семейства реестра: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() == family {
			return len(mf.GetMetric())
		}
	}
	return 0
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// packageGoFiles отдаёт пути .go-файлов каталога.
func packageGoFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}

// moduleRootFromMetrics поднимается от каталога пакета до go.mod.
func moduleRootFromMetrics(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("абсолютный путь пакета: %v", err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod не найден вверх от каталога пакета величин")
		}
		dir = parent
	}
}

// moduleProductionGoFiles обходит модуль и отдаёт не-тестовые .go-файлы.
func moduleProductionGoFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	sort.Strings(out)
	return out, err
}
