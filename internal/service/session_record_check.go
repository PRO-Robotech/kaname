// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// session_record_check.go — доводы способов и момента условия `mfa_fresh` из
// записи сессии ВОПРОСА (kaname#133, исход (а); приёмка
// `assurance-level-is-declared-by-our-session.md` §3.4, звено З1).
//
// # Откуда доводы и почему не из тела вопроса
//
// Вопрос о правах доступен на публичном слушателе, и вопрос о себе пропускает
// гейт полномочия вызывающего: тело вопроса — вход вызывающего, и довод о его
// же аутентификации, взятый оттуда, вызывающий назвал бы себе сам (CWE-807).
// Поэтому тело по-прежнему вырезается (`buildCondContext`), а доводы `amr_claims`
// и `mfa_at` служба выводит из СВОЕЙ записи сессии, на которую указывает номер
// записи, пересланный краем доверенным ключом фундамента
// (`x-kacho-token-session-id`, читатель — `internal/edgecredential`). Уровень —
// как прежде, доверенный, пересланный краем.
//
//   - `amr_claims` — множество предъявленного записи (Р2, слова словаря Р8);
//   - `mfa_at` — момент АУТЕНТИФИКАЦИИ записи (Р6, редакция 7): «3» в продукте
//     производит только выдача сессии входом ключом, поэтому момент
//     предъявления, обосновавшего уровень, и момент аутентификации совпадают.
//     Момент последнего предъявления доводом не служит: его двигает и пароль
//     (Ф11-37).
//
// # Когда запись годна
//
// Только когда она ЖИВА (не окончена, срок не вышел) на часах вопроса и её
// личность равна ДОВЕРЕННОЙ личности вопроса; иначе доводов нет — как у вопроса
// без нашей сессии (Ф11-43, -44, -48). Оба условия судит один оператор
// хранилища (`LiveSessionOf`), а не код после чтения: окончание между ответом
// службы краю о сессии и вопросом о правах — законный порядок двух вызовов, и
// живость судится на самом вопросе.
//
// Доводы прикладываются, только если вопрос — о самом вызывающем (`user:<его
// id>`): аутентификация вызывающего не описывает аутентификацию другого
// субъекта. Вопрос без ссылки, с недоверенной личностью либо от не-человека
// доводов не получает, и последнюю либо иную сессию личности служба вместо
// ссылки не подставляет.
//
// # Цена
//
// Запись читается лишь для вопроса, чей план достигает условного прямого
// списка (`authzplan.Plan.Conditioned`): доводы способов и момента читает только
// условие, и чтение записи на каждом вопросе края было бы платой ни за что.
// Партия читает запись не больше одного раза на проход.
package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// SessionRecords — порт: запись сессии человека, годная доводом условия.
//
// Реализует хранилище сессий (`internal/repo/kaname/pg.HumanSessionRepo`).
type SessionRecords interface {
	// LiveSessionOf — запись `id`, если она ЖИВА в момент `at` (не окончена,
	// срок позже `at`) и принадлежит личности `person`; иначе found=false.
	// Ошибка — хранилище не ответило.
	LiveSessionOf(ctx context.Context, id domain.HumanSessionID, person domain.UserID,
		at time.Time) (rec domain.HumanSession, found bool, err error)
}

// Ключи условного контекста, которые выводятся из записи сессии вопроса. Те же
// имена стоят в перечне вырезаемого из тела (`serverAuthoritativeCondKeys`).
const (
	condKeyAMR   = "amr_claims"
	condKeyMfaAt = "mfa_at"
)

// principalTypeUser — тип доверенной личности человека.
const principalTypeUser = "user"

// sessionEvidence — доводы одной записи; ok=false — доводов нет.
type sessionEvidence struct {
	ok      bool
	methods []string
	mfaAt   int64
}

// evidencePass — доводы на ОДИН проход (вопрос или партия): запись читается не
// больше одного раза, и ошибка запоминается вместе с ответом — повторять вопрос
// по пунктам партии значило бы платить за неполадку столько раз, сколько в ней
// позиций.
type evidencePass struct {
	once sync.Once
	ev   sessionEvidence
	err  error
}

// conditionedQuestion — достигает ли план вопроса условного прямого списка.
// Неразрешимый план — «нет»: вердикт по нему выносит форма, а доводы ему не
// нужны.
func conditionedQuestion(objectType, relation string) bool {
	plans, err := authzmodel.Shared()
	if err != nil {
		return false
	}
	plan, err := plans.Plan(objectType, relation)
	if err != nil {
		return false
	}
	return len(plan.Conditioned) > 0
}

// withSessionEvidence прикладывает к условному контексту плана доводы записи
// сессии вопроса. Ничего не приложено — условие остаётся без доводов и ложно.
func (s *AuthorizeService) withSessionEvidence(ctx context.Context, pass *evidencePass, p *checkPlan,
	now time.Time) error {
	if s.sessions == nil || p.condCtx == nil || !conditionedQuestion(p.objectType, p.relation) {
		return nil
	}
	principal, trusted := grpcsrv.TrustedPrincipalFromContext(ctx)
	if !trusted || principal.Type != principalTypeUser || principal.ID == "" ||
		p.subject != principalTypeUser+":"+principal.ID {
		return nil
	}
	pass.once.Do(func() {
		pass.ev, pass.err = s.readSessionEvidence(ctx, domain.UserID(principal.ID), now)
	})
	if pass.err != nil {
		return pass.err
	}
	if pass.ev.ok {
		p.condCtx[condKeyAMR] = pass.ev.methods
		p.condCtx[condKeyMfaAt] = pass.ev.mfaAt
	}
	return nil
}

// readSessionEvidence — один вопрос к хранилищу записей.
func (s *AuthorizeService) readSessionEvidence(ctx context.Context, person domain.UserID,
	now time.Time) (sessionEvidence, error) {
	id, ok := callerorigin.SessionIDFrom(ctx)
	if !ok {
		return sessionEvidence{}, nil
	}
	rec, found, err := s.sessions.LiveSessionOf(ctx, domain.HumanSessionID(id), person, now)
	if err != nil {
		return sessionEvidence{}, fmt.Errorf("%w: session record unavailable: %w", iamerr.ErrUnavailable, err)
	}
	if !found {
		return sessionEvidence{}, nil
	}
	methods := make([]string, len(rec.PresentedMethods))
	copy(methods, rec.PresentedMethods)
	return sessionEvidence{ok: true, methods: methods, mfaAt: rec.AuthenticatedAt.Unix()}, nil
}
