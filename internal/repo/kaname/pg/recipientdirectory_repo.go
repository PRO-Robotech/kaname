// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// recipientdirectory_repo.go — чтения справочника адресов (приёмка NTF-3 Р7):
// запись получателя, владелец аккаунта и аудитория версии события. Только
// чтение; запись и владелец — один оператор, аудитория — одна транзакция
// одного снимка. «Не найдено» различается ровно в одном месте —
// `errors.Is(err, pgx.ErrNoRows)`; любая иная ошибка уходит вызывающему, и тот
// отвечает `UNAVAILABLE` фиксированным текстом.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// RecipientDirectoryRepo — чтения справочника над пулом службы.
type RecipientDirectoryRepo struct {
	pool *pgxpool.Pool
}

// NewRecipientDirectoryRepo — конструктор над пулом службы.
func NewRecipientDirectoryRepo(pool *pgxpool.Pool) *RecipientDirectoryRepo {
	return &RecipientDirectoryRepo{pool: pool}
}

// ReadRecipient — запись получателя вида kind. found == false — записи нет.
func (r *RecipientDirectoryRepo) ReadRecipient(ctx context.Context, kind domain.RecipientKind, id string) (
	domain.RecipientRecord, bool, error,
) {
	var rec domain.RecipientRecord
	var err error
	switch kind {
	case domain.RecipientKindUser:
		err = r.pool.QueryRow(ctx, `
			SELECT invite_status = 'ACTIVE', email, email_verified_at IS NOT NULL
			  FROM kaname.users
			 WHERE id = $1`, id).Scan(&rec.Active, &rec.Email, &rec.EmailVerified)
	case domain.RecipientKindServiceAccount:
		// У учётной записи службы адреса нет никогда: читается только её
		// существование.
		var one int
		err = r.pool.QueryRow(ctx, `SELECT 1 FROM kaname.service_accounts WHERE id = $1`, id).Scan(&one)
	default:
		return domain.RecipientRecord{}, false, fmt.Errorf("read recipient: unknown recipient kind %d", kind)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RecipientRecord{}, false, nil
	}
	if err != nil {
		return domain.RecipientRecord{}, false, fmt.Errorf("read recipient: %w", err)
	}
	return rec, true, nil
}

// ReadAccountOwner — id пользователя-владельца аккаунта. found == false —
// аккаунта нет.
func (r *RecipientDirectoryRepo) ReadAccountOwner(ctx context.Context, accountID string) (string, bool, error) {
	var owner string
	err := r.pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id = $1`, accountID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read account owner: %w", err)
	}
	if owner == "" {
		return "", false, nil
	}
	return owner, true, nil
}

// ReadEventAudience — барьер поколения и страница аудитории версии события
// (Р30) ОДНИМ снимком: транзакция только чтения уровня REPEATABLE READ, первый
// оператор которой берёт снимок не старше токена (токен снят раньше вопроса).
//
// Порядок несущий: (1) снимок вопроса не старше `R_E` — иначе токен не выдан
// этой службой; (2) голова объекта несёт поколение не меньше `g_E` — иначе
// поколение не применено, вопрос не задаётся; (3) аудитория с оградой
// (`relverdict.FencedSubjects`).
func (r *RecipientDirectoryRepo) ReadEventAudience(ctx context.Context, q domain.EventAudienceQuestion) (
	domain.EventAudiencePage, error,
) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return domain.EventAudiencePage{}, fmt.Errorf("event audience: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Голова объекта названа словарём КАТАЛОГА (тем же, что зеркало); имя берётся
	// у живой строки каталога тем же порядком, что у вопроса о доступе.
	var tokenBehind bool
	var head *int64
	err = tx.QueryRow(ctx, `
		SELECT pg_snapshot_xmax($1::pg_snapshot) <= pg_snapshot_xmax(pg_current_snapshot()),
		       (SELECT h.generation
		          FROM kaname.object_head h
		         WHERE h.object_id = $3::text
		           AND h.object_type = (SELECT r.dotted
		                                  FROM kaname.catalog_resource r
		                                 WHERE r.object_type = $2::text
		                                 ORDER BY r.live DESC, r.dotted
		                                 LIMIT 1))`,
		q.AuthzRev, q.ObjectType, q.ObjectID).Scan(&tokenBehind, &head)
	if err != nil {
		return domain.EventAudiencePage{}, fmt.Errorf("event audience: barrier: %w", err)
	}
	if !tokenBehind {
		return domain.EventAudiencePage{Verdict: domain.EventAudienceTokenAhead}, nil
	}
	if head == nil || *head < q.Generation {
		return domain.EventAudiencePage{Verdict: domain.EventAudienceGenerationNotApplied}, nil
	}

	labels, err := json.Marshal(factLabels(q.Facts.Labels))
	if err != nil {
		return domain.EventAudiencePage{}, fmt.Errorf("event audience: labels: %w", err)
	}
	prev, err := json.Marshal(factLabels(q.Facts.PreviousLabels))
	if err != nil {
		return domain.EventAudiencePage{}, fmt.Errorf("event audience: previous labels: %w", err)
	}
	subjects, _, err := relverdict.FencedSubjects(ctx, tx, relverdict.FencedSubjectsQuery{
		ObjectType: q.ObjectType, ObjectID: q.ObjectID, Relation: audienceRelation,
		AuthzRev: q.AuthzRev, Scope: q.Facts.Scope(),
		LabelsJSON: string(labels), PreviousLabelsJSON: string(prev),
		ViaSubscription: q.ViaSubscription, Subject: q.Subject,
		AfterSubject: q.AfterSubject, Limit: q.Limit,
	})
	if err != nil {
		return domain.EventAudiencePage{}, fmt.Errorf("event audience: %w", err)
	}
	return domain.EventAudiencePage{Verdict: domain.EventAudienceAnswered, Subjects: subjects}, nil
}

// audienceRelation — отношение аудитории: читать объект (Р30, Д129 (1)).
const audienceRelation = "v_get"

// factLabels — метки фактов события; отсутствие — пустой объект, а не null:
// `null @> селектор` дало бы NULL, и ветвь меток молча не совпала бы ни с чем.
func factLabels(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
