// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modulecatalog

// plan.go — ВЕРДИКТ ОПОРЫ: отличает ПОЧИНКУ от КИРПИЧА.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`,
// §2.4 и §2.11; задача продукта #1034.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ПРОИЗВОДИТСЯ И ПОЧЕМУ НЕ АРИФМЕТИКОЙ
//
// Вопрос один: «выведет ли применение каталог за опору стража паритета». Ответ на
// него НЕ ЯВЛЯЕТСЯ функцией счётчиков применения, и это не мнение, а свойство
// задачи: два состояния — манифест ШИРЕ опоры и ОЖИВЛЕНИЕ снятой строки, которую
// опора объявляет, — неотличимы по паре «записано / снято» (1, 0) и требуют
// ПРОТИВОПОЛОЖНЫХ вердиктов. Значит вердикт производится сверкой, и сверка эта —
// ТА ЖЕ, что судит старт (`seed.MeasureCatalogParity`), а не её копия.
//
// ─────────────────────────────────────────────────────────────────────────────
// СОСТОЯНИЕ НЕСЁТ ОБЕ ПОЛОВИНЫ — ПО ПОСТРОЕНИЮ, А НЕ ПО ПАМЯТИ АВТОРА
//
// Порт стража (`seed.CatalogSource`) ДВУХметодный: живое множество и снятое.
// Подавший ему одно живое получит ЗАКОННОЕ СНЯТИЕ в `MissingRows` — то есть план
// объявит отказ там, где применение пройдёт, а следующий пуск состоится. План
// соврёт, и соврёт правдоподобно: наивное построение даёт ровно тот вердикт,
// которого ждали круги 1–3 приёмки.
//
// Поэтому половины не бывают по отдельности. `CatalogState` держит их
// НЕЭКСПОРТИРУЕМЫМИ полями, а единственный конструктор
// (`NewCatalogState(live, retired)`) требует обе ПОЗИЦИОННО: пропустить снятую
// сторону нельзя — её можно только назвать пустой, и это уже утверждение, а не
// умолчание. Двумя экспортируемыми полями то же самое записать нельзя:
// `CatalogState{Live: rows}` собралось бы молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ВЕРДИКТ НЕ ВЫВОДИТСЯ ИЗ `Diverged()` В ОДИНОЧКУ
//
// `Diverged()` ложен на переписи, в которой диффа НЕТ ВОВСЕ, — а такая перепись
// приезжает от НЕСОСТОЯВШЕГОСЯ измерения. Взяв её вердиктом, мы получили бы
// `WOULD_APPLY` на непрочитанном каталоге: разрешительный ответ там, где верно
// «не выполнилось». Цена измерена приёмкой: план объявляет `WOULD_APPLY` ⇒
// применение выводит каталог за опору ⇒ следующий пуск невозможен, и чинится это
// ручным SQL.
//
// Отсюда два условия, оба исполняются ЗДЕСЬ и оба видны в месте вызова:
//
//  1. отказ измерения не проглатывается: `err` от `seed.MeasureCatalogParity`
//     приводится к `ErrAnchorUnreadable`. У источника над значениями пути отказа
//     нет ни на одном входе (обе его половины возвращают `nil` безусловно) — и
//     именно потому эта ветка обязана быть написана, а не опущена: молчаливое
//     `census, _ :=` выглядит одинаково и при живом источнике, и при мёртвом;
//  2. перед вердиктом утверждается НЕПУСТОТА переписи — обеих её сторон. Пустая
//     сторона означает беспредметное сравнение, а не согласие.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЗДЕСЬ НЕТ
//
// Записи — никакой: `Plan` не пишет by construction, потому что писать нечем.
// Счётчиков переселения и вырезания — тоже: они суть свойство ТРАНЗАКЦИИ, а не
// чистого вычисления, и приезжают своей полосой.

import (
	"context"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
)

// Verdict — исход сверки состояния каталога с опорой стража паритета.
//
// Перечисление, а не булев признак: булев назвал бы СЕГОДНЯШНЮЮ единственную
// причину отказа своим именем, а перечисление оставляет место второй, не ломая
// контракт.
type Verdict string

const (
	// VerdictWouldApply — по опоре отказа не будет.
	//
	// Успеха применения НЕ обещает и обещать не может: состояние вправе
	// сдвинуться между планом и применением, а потолок последствий — быть
	// превышен. Утверждается ровно одно — опора не отвергнет.
	VerdictWouldApply Verdict = "WOULD_APPLY"
	// VerdictWouldBeRefusedBeyondAnchor — состояние вышло бы за опору: строка,
	// которой опора не знает, либо строка, которой опора требует, а её нет ни
	// живой, ни снятой.
	VerdictWouldBeRefusedBeyondAnchor Verdict = "WOULD_BE_REFUSED_BEYOND_ANCHOR"
)

var (
	// ErrAnchorUnreadable — сверка не состоялась: порт состояния не ответил.
	//
	// Отдельный отказ, а не «расхождений нет»: непрочитанный каталог не есть
	// сошедшийся каталог, и вердикт по нему не производится вовсе.
	ErrAnchorUnreadable = errors.New("modulecatalog: catalog parity could not be measured")
	// ErrAnchorCensusVoid — перепись беспредметна: одна из сторон сравнения
	// пуста, и «расхождений ноль» неотличимо от «сравнивать было нечего».
	ErrAnchorCensusVoid = errors.New("modulecatalog: catalog parity census is void")
	// ErrBeyondAnchor — применение вывело каталог за опору. Приходит ВНУТРИ
	// транзакции применителя и роняет её до коммита.
	ErrBeyondAnchor = errors.New("modulecatalog: applying would take the catalog beyond the parity anchor")
)

// CatalogState — состояние каталога ОБЕИМИ половинами: живой и снятой.
//
// Поля неэкспортируемы намеренно — см. шапку файла, «состояние несёт обе
// половины по построению».
type CatalogState struct {
	live    catalog.Rows
	retired catalog.Rows
}

// NewCatalogState — единственный конструктор состояния.
//
// Обе половины ПОЗИЦИОННЫЕ: снятую сторону нельзя пропустить, её можно только
// назвать пустой — и это утверждение вызывающего, а не умолчание типа.
func NewCatalogState(live, retired catalog.Rows) CatalogState {
	return CatalogState{live: live, retired: retired}
}

// AfterApplying — состояние каталога ПОСЛЕ применения объявленных строк.
//
// Обе половины двигаются, и это предмет:
//
//	объявленное манифестом  становится живым — в том числе ОЖИВАЕТ из снятого
//	живое этого модуля вне объявленного  становится СНЯТЫМ и остаётся
//	                                     свидетельством, а не исчезает
//	строки чужих модулей    не двигаются: применитель применяет ОДИН названный
//	                        манифест (`apply.go`, п. 1 шапки)
//
// Модуль оболочки при этом ОЖИВАЕТ безусловно: применение заводит либо оживляет
// его строку (`UpsertModule`), поэтому снятым он после применения не бывает.
func (s CatalogState) AfterApplying(d Declared) CatalogState {
	declaredRes := make(map[string]bool, len(d.Resources))
	for _, r := range d.Resources {
		declaredRes[resourcePair(r)] = true
	}
	declaredVerb := make(map[string]bool, len(d.Verbs))
	for _, v := range d.Verbs {
		declaredVerb[verbTriple(v)] = true
	}

	var next, gone catalog.Rows

	next.Modules = append(next.Modules, s.live.Modules...)
	if !namesModule(next.Modules, d.Module) {
		next.Modules = append(next.Modules, d.Module)
	}
	for _, m := range s.retired.Modules {
		if m != d.Module {
			gone.Modules = append(gone.Modules, m)
		}
	}

	for _, r := range s.live.Resources {
		switch {
		case r.Module != d.Module:
			next.Resources = append(next.Resources, r)
		case declaredRes[resourcePair(r)]:
			// Объявленную строку кладёт цикл объявленного ниже — здесь она
			// пропускается, чтобы не задвоиться ФОРМОЙ: имя типа модели
			// приводится к объявленному манифестом (`UpsertResource`), и живая
			// строка со старым именем после применения не остаётся.
		default:
			gone.Resources = append(gone.Resources, r)
		}
	}
	for _, r := range s.retired.Resources {
		if !declaredRes[resourcePair(r)] {
			gone.Resources = append(gone.Resources, r)
		}
	}
	next.Resources = append(next.Resources, d.Resources...)

	for _, v := range s.live.Verbs {
		switch {
		case v.Module != d.Module:
			next.Verbs = append(next.Verbs, v)
		case declaredVerb[verbTriple(v)]:
			// та же причина, что у ресурса выше: признак словаря приводится
			// объявленным (`UpsertVerb`).
		default:
			gone.Verbs = append(gone.Verbs, v)
		}
	}
	for _, v := range s.retired.Verbs {
		if !declaredVerb[verbTriple(v)] {
			gone.Verbs = append(gone.Verbs, v)
		}
	}
	next.Verbs = append(next.Verbs, d.Verbs...)

	return CatalogState{live: next, retired: gone}
}

// AnchorPlan — что сверка сказала о состоянии: вердикт и ТРИ корзины стража.
//
// Третья корзина — не украшение. Без неё оператор не отличит «сузил каталог, и
// это законно» от «ничего не менял»: обе картины дают пустые первые две и
// `WOULD_APPLY`, а последствия у них противоположны — во втором случае у
// арендатора ничего не отобрано, в первом отобрано и необратимо.
type AnchorPlan struct {
	// Verdict — исход сверки. Читается вместе с корзинами, а не вместо них.
	Verdict Verdict
	// BeyondAnchorExtra — строки, которые остались бы живыми, а опора их не
	// объявляет. Входят в вердикт.
	BeyondAnchorExtra []string
	// BeyondAnchorMissing — строки, которых после применения не будет НИ живыми,
	// НИ снятыми, а опора их объявляет. Входят в вердикт.
	BeyondAnchorMissing []string
	// WithdrawnRows — строки, которые применение СНИМЕТ, оставив свидетельство.
	// Законное сужение: в вердикт НЕ входит.
	WithdrawnRows []string
}

// anchorSource — порт стража (`seed.CatalogSource`) НАД ЗНАЧЕНИЯМИ.
//
// Пути отказа у него нет ни на одном входе: обе половины уже в памяти, и
// возвращать «не смог» ему нечем. Сигнатуру порта он тем не менее исполняет
// дословно — своей, «без ошибки», у стража не бывает, а завести её значило бы
// развести два способа спросить одно и то же.
type anchorSource struct{ state CatalogState }

// ReadLiveCatalog отдаёт живую половину. Ошибки не бывает — см. тип.
func (a anchorSource) ReadLiveCatalog(context.Context) (catalog.Rows, error) {
	return a.state.live, nil
}

// ReadRetiredCatalog отдаёт снятую половину. Ошибки не бывает — см. тип.
func (a anchorSource) ReadRetiredCatalog(context.Context) (catalog.Rows, error) {
	return a.state.retired, nil
}

// Соответствие порту стража — на этапе сборки: подать ему одну половину
// невозможно, потому что вторая объявлена тем же интерфейсом.
var _ seed.CatalogSource = anchorSource{}

// AnchorVerdictOf — вердикт опоры над ГОТОВЫМ состоянием каталога.
//
// Общий кусок обеих полос: `Plan` кормит его ГИПОТЕТИЧЕСКИМ состоянием,
// собранным из строк пула, применитель — ФАКТИЧЕСКИМ, прочитанным в своей
// транзакции после записи. Вопрос у обоих один, и потому производитель ответа
// тоже один.
func AnchorVerdictOf(ctx context.Context, state CatalogState) (AnchorPlan, error) {
	census, err := seed.MeasureCatalogParity(ctx, anchorSource{state: state})
	if err != nil {
		// Недостижимо by construction (см. `anchorSource`) — и написано ИМЕННО
		// поэтому: проглоченный отказ выглядит одинаково при живом источнике и
		// при мёртвом, а его перепись пуста, то есть даёт `WOULD_APPLY`.
		return AnchorPlan{}, fmt.Errorf("%w: %w", ErrAnchorUnreadable, err)
	}

	// НЕПУСТОТА — прежде вердикта. `Diverged()` ложен и на переписи, в которой
	// сравнения не было вовсе, поэтому «расхождений нет» обязано быть отличимо
	// от «сравнивать было нечего».
	if census.LiteralResources == 0 || census.Empty() {
		return AnchorPlan{}, fmt.Errorf(
			"%w: опора %d/%d/%d, живых строк %d/%d/%d — одна из сторон сравнения пуста, "+
				"и вердикт по такой переписи означал бы «расхождений нет» там, где верно "+
				"«сравнивать было нечего»",
			ErrAnchorCensusVoid,
			census.LiteralModules, census.LiteralResources, census.LiteralVerbs,
			census.RowModules, census.RowResources, census.RowVerbs)
	}

	plan := AnchorPlan{
		BeyondAnchorExtra:   census.ExtraRows,
		BeyondAnchorMissing: census.MissingRows,
		WithdrawnRows:       census.WithdrawnRows,
	}
	// Вердикт берётся у СУЩЕСТВУЮЩЕГО предиката стража, а не выражается второй
	// раз: асимметрия опоры (снятие в вердикт не входит) объявлена там, и
	// повторив её здесь, мы завели бы два места об одном предмете.
	if census.Diverged() {
		plan.Verdict = VerdictWouldBeRefusedBeyondAnchor
	} else {
		plan.Verdict = VerdictWouldApply
	}
	return plan, nil
}

// PlanAgainstAnchor — вердикт над ГИПОТЕТИЧЕСКИМ состоянием после применения
// объявленных строк к текущему.
//
// Ни записи, ни второго диффа: состояние строится значениями, сверка — та же.
func PlanAgainstAnchor(ctx context.Context, current CatalogState, d Declared) (AnchorPlan, error) {
	return AnchorVerdictOf(ctx, current.AfterApplying(d))
}

// resourcePair / verbTriple — ключи, которыми строку адресует СХЕМА
// (`catalog_resource_pkey (module, resource)`, `catalog_verb_pkey (module,
// resource, verb)`).
//
// Форма строки (имя типа модели, признак словаря) в ключ НЕ входит: применение
// приводит её оживлением, а не снимает и заводит заново, — ровно так же, как
// решает `stale` в `apply.go`.
func resourcePair(r catalog.ResourceRow) string { return r.Module + "." + r.Resource }

func verbTriple(v catalog.VerbRow) string { return v.Module + "." + v.Resource + "." + v.Verb }

// namesModule — перечень модулей уже называет этот.
func namesModule(modules []string, want string) bool {
	for _, m := range modules {
		if m == want {
			return true
		}
	}
	return false
}
