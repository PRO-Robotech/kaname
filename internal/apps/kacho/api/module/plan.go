// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module

// plan.go — `InternalModuleService.Plan`.
//
// План ЧИТАЕТ и не пишет: ни строк каталога, ни сирот, ни записи аудита. Это не
// самоограничение, а свойство состава: писателя ему не передано вовсе, и
// написать он не может, даже ошибившись.
//
// # Что план обязан различать, и почему без этого он бесполезен
//
// Два состояния дают ОДИНАКОВЫЕ счётчики и ПРОТИВОПОЛОЖНЫЙ исход применения:
// дрейф лишней строки при манифесте, сошедшемся с опорой (применение пройдёт), и
// манифест, объявивший строку, которой опора не знает (применение отвергнут
// внутри транзакции). Оператор по счётчикам не отличит починку от кирпича —
// поэтому план несёт ВЕРДИКТ опоры и три её корзины, а вердикт берётся у
// существующего предиката стража, а не выражается второй раз.

import (
	"context"
	"fmt"
	"sort"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// withdrawnListCap — потолок ОБОИХ перечней снимаемого.
//
// Перечень — рабочий список оператора, а не вердикт: вердикт несут корзины
// опоры, и они не усекаются вовсе (см. `beyondAnchorExtra` в контракте).
// Усечение объявляется признаком, а счётчик остаётся ТОЧНЫМ — иначе пустой хвост
// неотличим от «снимать больше нечего».
//
// Величина взята от популяции, а не наугад: действий в каталоге платформы
// низкие сотни, и модуль, снимающий больше сотни строк разом, есть событие, о
// котором оператор обязан узнать усечением, а не пролистыванием.
const withdrawnListCap = 100

// PlanUseCase — что применение доставленного манифеста этого модуля СДЕЛАЛО БЫ.
type PlanUseCase struct {
	delivery  DeliverySource
	catalogs  CatalogStateSource
	planState PlanStateSource
	// adminCheck — гейт права. nil ⇒ fail-closed (см. authz.go).
	adminCheck adminChecker
}

// NewPlanUseCase — конструктор. Гейт права провязывается отдельным оператором
// (`WithAdminChecker`), как у соседней кластерной службы.
func NewPlanUseCase(d DeliverySource, c CatalogStateSource, p PlanStateSource) *PlanUseCase {
	return &PlanUseCase{delivery: d, catalogs: c, planState: p}
}

// WithAdminChecker — провязка гейта права. Только композиционный корень.
func (uc *PlanUseCase) WithAdminChecker(c adminChecker) *PlanUseCase {
	uc.adminCheck = c
	return uc
}

// Execute — синхронное чтение.
func (uc *PlanUseCase) Execute(ctx context.Context, module string) (*iamv1.PlanModuleResponse, error) {
	// ГЕЙТ ПРАВА — ПЕРВЫМ СТЕЙТМЕНТОМ, до разбора входа и до всякого обращения к
	// базе. Порядок наблюдаем и потому проверяем: тот же вызывающий с заведомо
	// негодным именем модуля обязан получить отказ в правах, а НЕ отказ формы.
	// Обратный порядок отвечал бы на вопрос «существует ли такой модуль» тому,
	// кому отвечать не полагается.
	if err := requireClusterSystemAdmin(ctx, uc.adminCheck); err != nil {
		return nil, err
	}
	if module == "" {
		return nil, shared.InvalidArg("module", "required")
	}

	m, delivery, err := manifestFromDelivery(ctx, uc.delivery, module)
	if err != nil {
		return nil, err
	}
	// ОПОРА — из ТОЙ ЖЕ доставки, которой взят манифест (#1861). Оставь плану
	// образ, и он объявил бы отказ на модуле, который старт этого же процесса
	// принимает: два ответа об одном предмете, расходящиеся молча.
	deliveredAnchor, aerr := modulecatalog.AnchorOfDelivery(delivery)
	if aerr != nil {
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"опора паритета не собрана из доставки: %v", aerr))
	}
	declared, err := modulecatalog.RowsOf(m)
	if err != nil {
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"манифест модуля %s не даёт строк каталога: %v", module, err))
	}

	state, live, err := uc.readState(ctx)
	if err != nil {
		return nil, err
	}

	liveOfModule := rowsOfModule(live, module)
	// Отбор — ОБЩИЙ с применителем, а не второй его экземпляр.
	//
	// Прежде здесь стояла своя копия, и её довод был честен: «экспортировать
	// отбор применителя — правка соседнего пакета». Довод ИСТЁК — отбор
	// экспортирован (`modulecatalog.Withdrawn`) ради производителя плановой
	// стороны, которому нужно то же множество. Держать копию дальше значило бы
	// держать её ради причины, которой больше нет.
	//
	// Согласие прогоном (плановое число равно фактическому по каждой популяции)
	// при этом не отменяется и остаётся: оно судит СЧЁТ последствий, а не отбор
	// строк, и продолжает ловить расхождение предикатов SQL — то, чего общий
	// символ Go закрыть не может.
	staleResources, staleVerbs := modulecatalog.Withdrawn(liveOfModule, declared)

	anchor, err := modulecatalog.PlanAgainstAnchor(ctx, state, declared, deliveredAnchor)
	if err != nil {
		// Непрочитанный либо беспредметный каталог — НЕ «расхождений нет».
		// Отдать здесь `WOULD_APPLY` значило бы объявить применение безопасным по
		// переписи, которой не было.
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"вердикт опоры для модуля %s не получен: %v", module, err))
	}

	if uc.planState == nil {
		// Непровязанный производитель плановой стороны — отказ, а не нули.
		// Ноль в оценке последствий есть УТВЕРЖДЕНИЕ «ни одного права не
		// отберут», и вернув его, план соврал бы ровно о том, ради чего его
		// спрашивают. Отпечатка при этом тоже нет, значит и `Apply` подтвердить
		// нечем — поверхность отказывает целиком, а не наполовину.
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"производитель планового состояния каталога не провязан: отпечаток и оценки "+
				"последствий не производятся, и план не строится"))
	}
	ps, err := uc.planState.PlanState(ctx, module, staleResources, staleVerbs)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	withdrawnResourceNames := dottedResources(staleResources)
	withdrawnVerbNames := dottedVerbs(staleVerbs)
	writtenResources, writtenVerbs := writtenCounts(liveOfModule, declared)

	resList, resTrunc := capNames(withdrawnResourceNames)
	verbList, verbTrunc := capNames(withdrawnVerbNames)

	// Ширина чисел на проводе — 32 бита, и её хватает с запасом в два порядка:
	// каталог платформы измеряется единицами модулей, десятками ресурсов и низкой
	// сотней действий, а бюджет одного применения (`statement_timeout` пула)
	// исчерпывается сотнями тысяч строк переселения. Приведение поэтому не
	// теряет значения ни на одной величине.
	return &iamv1.PlanModuleResponse{
		Module:                 module,
		WithdrawnResources:     resList,
		WithdrawnVerbs:         verbList,
		WithdrawnResourceCount: safeconv.IntToInt32(len(withdrawnResourceNames)),
		WithdrawnVerbCount:     safeconv.IntToInt32(len(withdrawnVerbNames)),
		// Признак усечения — ОДИН на оба перечня: контракт объявляет его одним
		// полем, и усечение любого из двух означает для оператора одно и то же —
		// «перечень неполон, счётчик точен».
		WithdrawnListTruncated:              resTrunc || verbTrunc,
		WrittenResourceCount:                writtenResources,
		WrittenVerbCount:                    writtenVerbs,
		ResettledRuleRefsAtPlanTime:         safeconv.IntToInt32(ps.Resettled.RuleRefs),
		ResettledRoleVerbsAtPlanTime:        safeconv.IntToInt32(ps.Resettled.RoleVerbs),
		PrunedSelectorRowsAtPlanTime:        safeconv.IntToInt32(ps.Pruned.Rows),
		PrunedSelectorRowsDroppedAtPlanTime: safeconv.IntToInt32(ps.Pruned.Dropped),
		PrunedSelectorTypesAtPlanTime:       safeconv.IntToInt32(ps.Pruned.Elements),
		ExpectedState:                       ps.ExpectedState,
		BeyondAnchorExtra:                   anchor.BeyondAnchorExtra,
		BeyondAnchorMissing:                 anchor.BeyondAnchorMissing,
		WithdrawnRows:                       anchor.WithdrawnRows,
		Verdict:                             verdictToProto(anchor.Verdict),
	}, nil
}

// manifestFromDelivery — манифест названного модуля из ПЕРЕЧИТАННОЙ доставки.
//
// Три отказа, а не один: они чинятся в трёх разных местах — посадкой, источником
// манифестов и самим манифестом.
//
// Функция пакета, а не метод: оба глагола входа берут манифест ОДИНАКОВО, и
// вторая копия этого разбора разошлась бы с первой молча — план объявлял бы
// доставку сорванной там, где применение объявляет её необъявленной.
// Возвращается ДВОЕ: названный манифест и ВСЯ доставка. Вторая нужна опоре
// паритета (#1861), и берётся она ТЕМ ЖЕ чтением: второй проход по каталогу
// доставки был бы вторым местом об одном предмете — выбрали бы один манифест, а
// опору построили по другому составу, и разошлось бы это молча.
func manifestFromDelivery(ctx context.Context, src DeliverySource, module string) (*manifest.Manifest, []*manifest.Manifest, error) {
	if src == nil {
		return nil, nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"источник доставки манифестов не провязан"))
	}
	d, err := src.Read(ctx)
	switch {
	case err != nil:
		// Объявлена и СОРВАНА. Числа входят в отказ: без них оператор не знает,
		// прочитано ли хоть что-нибудь.
		return nil, nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"доставка манифестов объявлена посадкой и сорвана: прочитано манифестов %d, "+
				"находок %d; чинится источником манифестов, а не повтором запроса: %v",
			d.ManifestsRead, d.Findings, err))
	case !d.Declared:
		// НЕ ОБЪЯВЛЕНА. Отдельный отказ и отдельный текст: чинится посадкой.
		return nil, nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"доставка манифестов модулей не объявлена посадкой: применять и планировать "+
				"нечего; чинится посадкой (ручка каталога доставки), а не повтором запроса"))
	}
	for _, m := range d.Manifests {
		if m != nil && m.Module == module {
			return m, d.Manifests, nil
		}
	}
	// Манифеста модуля в доставке НЕТ. Говорится прямо, что это не снятие: иначе
	// оператор прочтёт отказ как «модуль снят» и пойдёт восстанавливать то, чего
	// никто не снимал.
	return nil, nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound,
		"Module %s not found in the delivered manifests: отсутствие манифеста снятием "+
			"модуля НЕ является; проверьте, что источник манифестов кладёт манифест "+
			"этого модуля в объявленный посадкой каталог доставки (прочитано манифестов %d)",
		module, d.ManifestsRead))
}

// readState — обе половины каталога платформы ОДНИМ читателем.
func (uc *PlanUseCase) readState(ctx context.Context) (modulecatalog.CatalogState, catalog.Rows, error) {
	if uc.catalogs == nil {
		return modulecatalog.CatalogState{}, catalog.Rows{}, shared.MapRepoErr(
			iamerr.Wrapf(iamerr.ErrFailedPrecondition, "читатель каталога не провязан"))
	}
	live, err := uc.catalogs.ReadLiveCatalog(ctx)
	if err != nil {
		return modulecatalog.CatalogState{}, catalog.Rows{}, shared.MapRepoErr(
			fmt.Errorf("прочитать живой каталог: %w", err))
	}
	retired, err := uc.catalogs.ReadRetiredCatalog(ctx)
	if err != nil {
		return modulecatalog.CatalogState{}, catalog.Rows{}, shared.MapRepoErr(
			fmt.Errorf("прочитать снятый каталог: %w", err))
	}
	return modulecatalog.NewCatalogState(live, retired), live, nil
}

// verdictToProto — перечисление вердикта на проводе.
//
// Неназванный вердикт остаётся `UNSPECIFIED` НАМЕРЕННО: подставив ему одно из
// двух значений, мы объявили бы клиенту исход, которого производитель не
// называл.
func verdictToProto(v modulecatalog.Verdict) iamv1.ModulePlanVerdict {
	switch v {
	case modulecatalog.VerdictWouldApply:
		return iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_APPLY
	case modulecatalog.VerdictWouldBeRefusedBeyondAnchor:
		return iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_BEYOND_ANCHOR
	default:
		return iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_UNSPECIFIED
	}
}

// rowsOfModule — живые строки ОДНОГО модуля.
func rowsOfModule(all catalog.Rows, module string) catalog.Rows {
	var out catalog.Rows
	for _, m := range all.Modules {
		if m == module {
			out.Modules = append(out.Modules, m)
		}
	}
	for _, r := range all.Resources {
		if r.Module == module {
			out.Resources = append(out.Resources, r)
		}
	}
	for _, v := range all.Verbs {
		if v.Module == module {
			out.Verbs = append(out.Verbs, v)
		}
	}
	return out
}

// writtenCounts — сколько строк применение ЗАВЕЛО БЫ либо ОЖИВИЛО.
//
// Считается по тому же признаку, по которому применитель отличает «записано» от
// «уже стояло»: строка нова, если её ключа нет среди живых ЛИБО её форма
// (имя типа модели / признак словаря) отличается от объявленной.
func writtenCounts(live catalog.Rows, declared modulecatalog.Declared) (int32, int32) {
	liveRes := make(map[string]catalog.ResourceRow, len(live.Resources))
	for _, r := range live.Resources {
		liveRes[dottedResource(r)] = r
	}
	liveVerb := make(map[string]catalog.VerbRow, len(live.Verbs))
	for _, v := range live.Verbs {
		liveVerb[dottedVerb(v)] = v
	}

	var res, verbs int32
	for _, r := range declared.Resources {
		cur, ok := liveRes[dottedResource(r)]
		if !ok || cur.ObjectType != r.ObjectType {
			res++
		}
	}
	for _, v := range declared.Verbs {
		cur, ok := liveVerb[dottedVerb(v)]
		if !ok || cur.PerObject != v.PerObject {
			verbs++
		}
	}
	return res, verbs
}

// dottedResource / dottedVerb — ключи схемы, они же имена строк на проводе.
func dottedResource(r catalog.ResourceRow) string { return r.Module + "." + r.Resource }
func dottedVerb(v catalog.VerbRow) string {
	return v.Module + "." + v.Resource + "." + v.Verb
}

func dottedResources(rows []catalog.ResourceRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, dottedResource(r))
	}
	sort.Strings(out)
	return out
}

func dottedVerbs(rows []catalog.VerbRow) []string {
	out := make([]string, 0, len(rows))
	for _, v := range rows {
		out = append(out, dottedVerb(v))
	}
	sort.Strings(out)
	return out
}

// capNames — перечень, усечённый до потолка, и признак усечения.
//
// Порядок задан ВЫЗЫВАЮЩИМ (лексикографический): без него усечение отдавало бы
// произвольное подмножество, разное на двух вызовах над одним состоянием.
func capNames(names []string) ([]string, bool) {
	if len(names) <= withdrawnListCap {
		return names, false
	}
	return names[:withdrawnListCap], true
}
