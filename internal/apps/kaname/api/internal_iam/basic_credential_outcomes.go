// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"log/slog"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕПИСЬ ИСХОДОВ ПОЛОСЫ БАЗОВОГО СЕКРЕТА (задача kaname#379)
//
// Наружу полоса отвечает одним отказом на любую причину — различимый отказ был
// бы оракулом. Внутри тот же отказ обязан различаться: без этого отсечка
// отзыва-всех, сработавшая тысячу раз, неотличима от перебора секрета и от
// контроля, не сработавшего ни разу. Различимость живёт здесь — в переписи по
// глаголу и исходу и в структурной записи журнала, — и больше нигде.
//
// Перепись заведена ЦЕЛИКОМ по закрытому словарю, а не по мере встречаемости:
// клетка, появляющаяся при первом попадании, не отличает «ноль отказов по
// отсечке» от «исхода без счётчика». Её читает витрина корня.

// BasicCredentialVerb — глагол полосы базового секрета. Закрытый словарь.
type BasicCredentialVerb string

const (
	// BasicCredentialResolve — вердикт о предъявленном секрете.
	BasicCredentialResolve BasicCredentialVerb = "resolve"
	// BasicCredentialLiveness — живость удостоверения по идентификатору.
	BasicCredentialLiveness BasicCredentialVerb = "liveness"
)

// basicCredentialVerbs — словарь глаголов в объявленном порядке.
func basicCredentialVerbs() []BasicCredentialVerb {
	return []BasicCredentialVerb{BasicCredentialResolve, BasicCredentialLiveness}
}

// BasicCredentialOutcome — исход глагола. Закрытый словарь: принято, отказ по
// каждой причине [domain.BasicCredentialRefusalReasons] (значение исхода —
// дословно имя причины), отказ без названной причины и «авторитет не ответил».
type BasicCredentialOutcome string

const (
	// BasicOutcomeAccepted — предъявленное принято либо удостоверение живо.
	// Знаменатель: без него «ноль отказов» неотличим от «полоса не исполнялась».
	BasicOutcomeAccepted BasicCredentialOutcome = "accepted"
	// BasicOutcomeReasonUnnamed — авторитет отказал, не назвав причины. Это
	// нарушение его контракта, и оно считается своей клеткой, а не
	// подставленной причиной: подставленная выглядела бы фактом.
	BasicOutcomeReasonUnnamed BasicCredentialOutcome = "reason-unnamed"
	// BasicOutcomeUnavailable — состояние удостоверения установить не удалось:
	// авторитет не провязан либо не ответил. Чинит оператор, а не предъявитель.
	BasicOutcomeUnavailable BasicCredentialOutcome = "unavailable"
)

// BasicCredentialCell — клетка переписи: глагол и его исход.
type BasicCredentialCell struct {
	Verb    BasicCredentialVerb
	Outcome BasicCredentialOutcome
}

// DeclaredBasicCredentialCells — все клетки переписи, в объявленном порядке.
//
// Отдаётся наружу ради витрины: её ряды обязаны совпадать с клетками переписи
// by construction. Причины берутся из словаря домена, а не выписываются здесь
// второй копией.
func DeclaredBasicCredentialCells() []BasicCredentialCell {
	reasons := domain.BasicCredentialRefusalReasons()
	out := make([]BasicCredentialCell, 0, len(basicCredentialVerbs())*(len(reasons)+3))
	for _, verb := range basicCredentialVerbs() {
		out = append(out, BasicCredentialCell{Verb: verb, Outcome: BasicOutcomeAccepted})
		for _, r := range reasons {
			out = append(out, BasicCredentialCell{Verb: verb, Outcome: BasicCredentialOutcome(r)})
		}
		out = append(out,
			BasicCredentialCell{Verb: verb, Outcome: BasicOutcomeReasonUnnamed},
			BasicCredentialCell{Verb: verb, Outcome: BasicOutcomeUnavailable})
	}
	return out
}

// basicCredentialCensus — перепись исходов. Нулевое значение готово к работе:
// обработчик собирается и литералом, и перепись обязана считать с первого
// вопроса, а не с первой провязки.
type basicCredentialCensus struct {
	mu     sync.Mutex
	counts map[BasicCredentialCell]uint64
}

func (c *basicCredentialCensus) count(cell BasicCredentialCell) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = make(map[BasicCredentialCell]uint64)
	}
	c.counts[cell]++
}

// snapshot — снимок по ВСЕМ объявленным клеткам, включая нулевые.
func (c *basicCredentialCensus) snapshot() map[BasicCredentialCell]uint64 {
	declared := DeclaredBasicCredentialCells()
	out := make(map[BasicCredentialCell]uint64, len(declared))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cell := range declared {
		out[cell] = c.counts[cell]
	}
	return out
}

// BasicCredentialOutcomes — перепись исходов полосы. Читается витриной корня.
func (h *Handler) BasicCredentialOutcomes() map[BasicCredentialCell]uint64 {
	return h.basicOutcomes.snapshot()
}

// countBasic кладёт исход глагола в перепись.
func (h *Handler) countBasic(verb BasicCredentialVerb, outcome BasicCredentialOutcome) {
	h.basicOutcomes.count(BasicCredentialCell{Verb: verb, Outcome: outcome})
}

// refusalOutcome — клетка отказа по причине, которую назвал авторитет.
// Причина вне словаря либо не названная вовсе — [BasicOutcomeReasonUnnamed].
func refusalOutcome(err error) BasicCredentialOutcome {
	reason, named := domain.BasicCredentialRefusalReasonOf(err)
	if !named {
		return BasicOutcomeReasonUnnamed
	}
	for _, known := range domain.BasicCredentialRefusalReasons() {
		if reason == known {
			return BasicCredentialOutcome(reason)
		}
	}
	return BasicOutcomeReasonUnnamed
}

// refuseBasic — единый отказ наружу и его причина внутрь.
//
// Наружу — ОДИН код и ОДИН текст на любую причину. Внутрь — клетка переписи и
// структурная запись журнала: глагол и исход, и больше ничего. Ни
// предъявленной строки, ни идентификатора в записи нет: первое — секрет, второе
// на отказе «форма негодна» есть произвольный вход предъявителя.
func (h *Handler) refuseBasic(ctx context.Context, verb BasicCredentialVerb, err error) error {
	outcome := refusalOutcome(err)
	h.countBasic(verb, outcome)
	if h.logger != nil {
		level := slog.LevelInfo
		if outcome == BasicOutcomeReasonUnnamed {
			// Предъявитель тут ни при чём: авторитет нарушил свой контракт.
			level = slog.LevelWarn
		}
		h.logger.Log(ctx, level, "basic credential refused",
			slog.String("verb", string(verb)), slog.String("outcome", string(outcome)))
	}
	return status.Error(codes.Unauthenticated, refusalText)
}
