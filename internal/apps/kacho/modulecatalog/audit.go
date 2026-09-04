// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modulecatalog

// audit.go — ПРИМЕНЕНИЕ ОСТАВЛЯЕТ СЛЕД, и след называет того, кто применил
// (задача продукта #1034, приёмка §2.7).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ СЛЕД, ЕСЛИ ЕСТЬ ЖУРНАЛ И СЧЁТЧИКИ
//
// Журнал печатает перепись, счётчик двигает величину — оба говорят, ЧТО
// произошло, и ни один не говорит, КТО это сделал. Применение отбирает у
// арендатора права необратимо (переселение проекций и вырезание типов из
// селекторов), и починка боевой базы глаголом обязана быть отличима от починки
// руками. Без записи она неотличима.
//
// ─────────────────────────────────────────────────────────────────────────────
// АКТОР — ИЗ ПРОВЕРЕННОЙ ЛИЧНОСТИ, И ПОДСТАВЛЯТЬ ЕГО НЕЛЬЗЯ
//
// `operations.PrincipalFromContext` на запросе БЕЗ личности возвращает
// `SystemPrincipal()` — это её объявленное поведение, а не дефект. Аудит,
// взявший актора ею, запишет `system` там, где действовал оператор: это не
// пропуск, а ЛОЖНОЕ УТВЕРЖДЕНИЕ о том, кто это сделал, и оно хуже отсутствия
// записи — отсутствие видно, ложь нет. Различает состояния только
// `PrincipalFromContextOK` вторым значением, и глагол на `ok=false`
// ОТКАЗЫВАЕТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОС ДВЕ, И АКТОР У НИХ РАЗНЫЙ ПО ПОСТРОЕНИЮ, А НЕ ПО УМОЛЧАНИЮ
//
//	путь ГЛАГОЛА (`VerbApplier`)  актор — проверенная личность вызывающего;
//	                              её нет ⇒ ErrNoVerifiedActor, до транзакции
//	путь СТАРТА  (`Applier`)      вызывающего нет BY CONSTRUCTION: применение
//	                              идёт до подъёма слушателей, запроса не
//	                              существует. Актор — НАЗВАННЫЙ процессный,
//	                              `BootActorID`
//
// Полосу выбирает ТИП, а не значение поля и не содержимое контекста: у
// `VerbApplier` пути мимо проверенной личности нет ни одного, у `Applier`
// процессный актор стоит ЯВНЫМ значением. Нулевое значение `applyLane` —
// полоса глагола, то есть fail-closed: забытая полоса означает «спросить, кто
// это», а не «записать за систему».
//
// Путь старта личность из контекста НЕ читает намеренно. Прочитай он её —
// и запись зависела бы от того, не положил ли кто-нибудь принципала в
// контекст процесса; сегодня это никто, но «сегодня никто» держится памятью, а
// названный процессный актор держится построением.

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// AppliedEventType — вид события следа применения.
//
// Форма удовлетворяет ключу схемы `audit_outbox_event_type_check`
// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`): три сегмента, подчёркивание внутри
// сегмента законно. Объявлен ЗДЕСЬ, а не в адаптере: вид события — факт
// предметной области, а не деталь хранения.
const AppliedEventType = "iam.module_catalog.applied"

// Источник применения. Набор ЗАКРЫТ и приходит из полосы, никогда из запроса.
const (
	// SourceVerb — применение позвано глаголом, в обслуживающем процессе.
	SourceVerb = "rpc"
	// SourceBoot — применение позвано композиционным корнем на старте.
	SourceBoot = "boot"
)

// BootActorID — НАЗВАННЫЙ процессный актор пути старта.
//
// Не пусто и не «аноним»: обе эти строки означали бы «неизвестно кто», а
// применение на старте делает вполне определённый исполнитель — сам процесс,
// приводящий каталог к доставленным манифестам. Значение стоит здесь ЯВНО и
// в единственном экземпляре; сравнение с ним осмысленно, чего нельзя сказать
// ни о пустой строке, ни о зарезервированном слове анонимности.
const BootActorID = "iam-module-catalog-boot"

// ErrNoVerifiedActor — применение позвано глаголом на запросе БЕЗ проверенной
// личности.
//
// Отказ, а не подстановка: запись о необратимом отборе прав арендатора,
// оставленная за подставленным `system`, есть ложное утверждение об авторе
// действия. Приходит ДО открытия транзакции — «кто применяет» есть предусловие
// глагола, а не деталь записи.
var ErrNoVerifiedActor = errors.New("modulecatalog: applying by verb requires a verified caller identity")

// actor — кто применяет, и откуда это известно.
//
// Тип неэкспортируемый: актора выбирает ПОЛОСА, а не вызывающий. Экспортируй
// его — и появился бы вход, на котором вызывающий называет автора сам, то есть
// ровно то, что §2.7 запрещает словами «никогда из тела».
type actor struct {
	// id — идентификатор автора действия. Пустым не бывает: обе полосы дают
	// непустое значение либо отказывают.
	id string
	// source — какая полоса применяла.
	source string
}

// actorOf — актор полосы.
//
// Путь глагола спрашивает КОНТЕКСТ и отказывает, если проверенной личности
// нет. Путь старта не спрашивает ничего: вызывающего у него нет by
// construction, и процессный актор назван константой.
func actorOf(lane applyLane, principal operations.Principal, established bool) (actor, error) {
	if lane == laneBootLeavesTheAnchorToTheGuard {
		return actor{id: BootActorID, source: SourceBoot}, nil
	}
	if !established || principal.IsAnonymous() {
		return actor{}, fmt.Errorf("%w: применение отвергнуто до открытия транзакции", ErrNoVerifiedActor)
	}
	return actor{id: principal.ID, source: SourceVerb}, nil
}

// AppliedEvent — след ОДНОГО применения.
//
// Тип, а не карта: карта позволяет забыть ключ, и забыт был бы именно тот,
// который никто не спросит до разбора последствий. Собирается ОДНИМ
// конструктором из переписи применения, поэтому «величина в переписи есть, а в
// следе нет» невыразимо иначе как правкой обоих мест сразу.
type AppliedEvent struct {
	// Actor — автор действия. Проверенная личность вызывающего либо названный
	// процессный актор старта; подставленного `system` здесь не бывает.
	Actor string
	// Source — полоса применения: `rpc` либо `boot`.
	Source string
	// Module — модуль, каталог которого приведён к манифесту.
	Module string
	// ExpectedState — подтверждение, названное вызывающим. Пусто на пути
	// старта: подтверждения там нет и быть не может (§2.5).
	ExpectedState string
	// MaxResettledRuleRefs / MaxResettledRoleVerbs — потолки последствий,
	// названные вызывающим. `nil` на пути старта — там их нет.
	MaxResettledRuleRefs  *int
	MaxResettledRoleVerbs *int
	// Written* / Retired* — сколько строк каталога заведено, оживлено и снято.
	WrittenResources int
	WrittenVerbs     int
	RetiredResources int
	RetiredVerbs     int
	// Resettled — ПЕРВАЯ и ВТОРАЯ популяции последствий: переселённые в сироты
	// проекции арендаторских ролей.
	Resettled Resettled
	// PrunedSelectorRows / PrunedSelectorRowsDropped / PrunedSelectorTypes —
	// ТРЕТЬЯ популяция последствий.
	//
	// Несёт все три величины, и это НЕСУЩЕЕ, а не полнота ради полноты: у
	// третьей популяции нет ни потолка (§2.6 — потолок здесь запрещал бы
	// починку), ни ведомости — вырезанное не помнит НИЧТО. Значит эта запись
	// есть ЕДИНСТВЕННЫЙ след того, что было вырезано. План, печатающий три
	// величины, при следе, их не несущем, даёт оператору уверенность, что след
	// останется, — а следа нет.
	PrunedSelectorRows        int
	PrunedSelectorRowsDropped int
	PrunedSelectorTypes       int
}

// appliedEventOf собирает след из переписи применения — ОДНИМ местом.
func appliedEventOf(a actor, rep Report, conf *confirmation) AppliedEvent {
	ev := AppliedEvent{
		Actor:                     a.id,
		Source:                    a.source,
		Module:                    rep.Module,
		WrittenResources:          rep.WrittenResources,
		WrittenVerbs:              rep.WrittenVerbs,
		RetiredResources:          rep.RetiredResources,
		RetiredVerbs:              rep.RetiredVerbs,
		Resettled:                 rep.Resettled,
		PrunedSelectorRows:        rep.PrunedSelectorRows,
		PrunedSelectorRowsDropped: rep.PrunedSelectorRowsDropped,
		PrunedSelectorTypes:       rep.PrunedSelectorTypes,
	}
	if conf != nil {
		ev.ExpectedState = conf.expectedState
		ev.MaxResettledRuleRefs = conf.maxResettledRuleRefs
		ev.MaxResettledRoleVerbs = conf.maxResettledRoleVerbs
	}
	return ev
}

// Payload — тело записи следа.
//
// Имена ключей решает use-case, а не хранилище (`outboxtypes.AuditEvent`
// говорит это дословно), поэтому карта собирается ЗДЕСЬ, а адаптер её только
// заворачивает. Ключи, которых у полосы нет, не ставятся ВОВСЕ: пустое значение
// обязано означать «пусто», а «подтверждения не было» и «подтверждение пустое»
// — разные утверждения.
func (e AppliedEvent) Payload() map[string]any {
	p := map[string]any{
		"actor":                        e.Actor,
		"source":                       e.Source,
		"module":                       e.Module,
		"written_resources":            e.WrittenResources,
		"written_verbs":                e.WrittenVerbs,
		"retired_resources":            e.RetiredResources,
		"retired_verbs":                e.RetiredVerbs,
		"resettled_rule_refs":          e.Resettled.RuleRefs,
		"resettled_role_verbs":         e.Resettled.RoleVerbs,
		"pruned_selector_rows":         e.PrunedSelectorRows,
		"pruned_selector_rows_dropped": e.PrunedSelectorRowsDropped,
		"pruned_selector_types":        e.PrunedSelectorTypes,
	}
	if e.ExpectedState != "" {
		p["expected_state"] = e.ExpectedState
	}
	if e.MaxResettledRuleRefs != nil {
		p["max_resettled_rule_refs"] = *e.MaxResettledRuleRefs
	}
	if e.MaxResettledRoleVerbs != nil {
		p["max_resettled_role_verbs"] = *e.MaxResettledRoleVerbs
	}
	return p
}

// String — след одной строкой, для журнала разбора.
func (e AppliedEvent) String() string {
	limits := "нет"
	if e.MaxResettledRuleRefs != nil && e.MaxResettledRoleVerbs != nil {
		limits = strconv.Itoa(*e.MaxResettledRuleRefs) + "/" + strconv.Itoa(*e.MaxResettledRoleVerbs)
	}
	return fmt.Sprintf(
		"след %s: модуль %s · актор %s · источник %s · потолки %s · "+
			"записано %d/%d · снято %d/%d · переселено %d/%d · вырезано %d/%d/%d",
		AppliedEventType, e.Module, e.Actor, e.Source, limits,
		e.WrittenResources, e.WrittenVerbs,
		e.RetiredResources, e.RetiredVerbs,
		e.Resettled.RuleRefs, e.Resettled.RoleVerbs,
		e.PrunedSelectorRows, e.PrunedSelectorRowsDropped, e.PrunedSelectorTypes)
}
