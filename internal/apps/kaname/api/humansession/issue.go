// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// issue.go — ОПЕРАЦИЯ ВЫДАЧИ сессии (Р1, Р5, Д10): зовётся ИЗНУТРИ транзакции
// выдающего глагола — входом здесь, регистрацией (Ф4) и восстановлением (Ф5) —
// а не отдельным вызовом по сети: иначе отказ записи строки сессии не откатывал
// бы глагол целиком (Ф4-04).
//
// Момент и уровень назначает ЭТА операция (F4d-21): вызывающий приносит
// множество предъявленного, всё остальное — здесь.

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// sessionIDPrefix — приставка идентификатора записи в дефисном каноне. Наружу
// не адресуется (Р1), поэтому в платформенный каталог приставок не входит.
const sessionIDPrefix = "hss"

// Событие аудита выдачи сессии (Р14). Регистрация и восстановление своего
// события входа не дублируют — их различают их события (Ф3-47).
const AuditSessionIssued = "iam.session.issued"

// IssueInput — что приносит выдающий глагол.
type IssueInput struct {
	User domain.User
	// Presented — множество предъявленного (Ф11 Р2); уровень выводится
	// правилом, а не приносится.
	Presented []assurance.Presentation
	// At — момент аутентификации (часы полосы, форма Ф-д).
	At time.Time
	// TTL — срок с момента выдачи (настройка, Р3).
	TTL time.Duration
	// EmitAudit — писать ли событие выдачи здесь; выдающий глагол, у которого
	// своё событие (регистрация, восстановление), выключает.
	EmitAudit bool
}

// IssueSession — запись, память первой аутентификации и (если просили)
// событие — ОДНОЙ транзакцией writer'а вызывающего. Возвращает записанную
// сессию и свежий носитель.
func IssueSession(ctx context.Context, w Writer, in IssueInput) (domain.HumanSession, domain.SessionBearer, error) {
	if in.User.ID == "" {
		return domain.HumanSession{}, domain.SessionBearer{}, fmt.Errorf("issue session: user required")
	}
	if in.TTL <= 0 {
		return domain.HumanSession{}, domain.SessionBearer{}, fmt.Errorf("issue session: ttl must be positive")
	}
	if in.At.IsZero() {
		return domain.HumanSession{}, domain.SessionBearer{}, fmt.Errorf("issue session: moment required")
	}
	level, ok := assurance.LevelOf(in.Presented)
	if !ok {
		return domain.HumanSession{}, domain.SessionBearer{}, fmt.Errorf("issue session: presented methods yield no assurance level")
	}
	methods := make([]string, 0, len(in.Presented))
	for _, p := range in.Presented {
		methods = append(methods, p.Method().String())
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		return domain.HumanSession{}, domain.SessionBearer{}, err
	}
	at := in.At.UTC()
	s := domain.HumanSession{
		ID:               domain.HumanSessionID(ids.NewHyphenID(sessionIDPrefix)),
		UserID:           in.User.ID,
		AuthenticatedAt:  at,
		LastPresentedAt:  at,
		ExpiresAt:        at.Add(in.TTL),
		AssuranceLevel:   level.String(),
		PresentedMethods: methods,
	}
	if err := w.InsertSession(ctx, s, bearer.Digest()); err != nil {
		return domain.HumanSession{}, domain.SessionBearer{}, err
	}
	if err := w.RememberFirstAuthentication(ctx, in.User.ID, at); err != nil {
		return domain.HumanSession{}, domain.SessionBearer{}, err
	}
	if in.EmitAudit {
		if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
			EventType:       AuditSessionIssued,
			TenantAccountID: string(in.User.AccountID),
			// Без адреса и без имени (гейт `audit_payload_pii`): субъект назван
			// неизменяемым идентификатором, сессия — своим.
			Payload: map[string]any{
				"user_id":    string(in.User.ID),
				"session_id": string(s.ID),
				"methods":    methods,
			},
		}); err != nil {
			return domain.HumanSession{}, domain.SessionBearer{}, err
		}
	}
	return s, bearer, nil
}
