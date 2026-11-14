// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	"github.com/jackc/pgx/v5"
)

// ErrAdministrativeSourceUnconfirmed отличает неизвестное происхождение от
// отказа известного истёкшего источника. Ошибки БД и бюджета им не маскируются.
var ErrAdministrativeSourceUnconfirmed = errors.New("administrative source unconfirmed")
var ErrAdministrativeSourceLimit = errors.New("administrative source budget exceeded")

// AdministrativeReadBudget общий для native страниц и проверок их источников.
// Пределы совпадают с bounded actor source census; достижение предела — ошибка.
type AdministrativeReadBudget struct{ rows, reads int }

func (b *AdministrativeReadBudget) Charge(rows, reads int) error {
	if rows < 0 || reads < 0 || rows > 100000-b.rows || reads > 4096-b.reads {
		return ErrAdministrativeSourceLimit
	}
	b.rows += rows
	b.reads += reads
	return nil
}

type AdministrativeFact struct {
	ObjectType, ObjectID, Relation, Subject, ConditionName string
	QuestionRelation                                       string
	ConditionParameters                                    map[string]any
}
type AdministrativeVerifier func(context.Context, AdministrativeFact, *AdministrativeReadBudget) (bool, error)

// AdministrativeAsker переопределяет только прямой mutation-вопрос. Модель,
// speaker/scopes, условие и ordinary grant arm остаются штатными. Публичный
// read Asker и обратные вопросы не изменяются; наружу передаётся узкий Check.
type AdministrativeAsker struct {
	*Asker
	decision    func() time.Time
	verifier    AdministrativeVerifier
	boundary    AdministrativeReadBoundary
	budget      *AdministrativeReadBudget
	bound       bool
	budgetBound bool
}

func NewAdministrativeAsker(tx pgx.Tx, plans PlanSource, decision func() time.Time, verifier AdministrativeVerifier) *AdministrativeAsker {
	return &AdministrativeAsker{Asker: &Asker{transaction: tx, preparedPlans: plans}, decision: decision, verifier: verifier}
}

// BindReadBudget связывает общий бюджет попытки, сохраняя полную native SQL
// популяцию. Pg wrapper уже списал existence/admission до dispatch.
// Явный nil даёт отказ, а не новый бюджет для каждого вопроса.
func (a *AdministrativeAsker) BindReadBudget(budget *AdministrativeReadBudget) {
	a.budget, a.budgetBound = budget, true
}

func (a *AdministrativeAsker) Allowed(ctx context.Context, subject, typ, id, relation string, input map[string]any) (bool, error) {
	if a == nil || a.Asker == nil || a.transaction == nil || a.preparedPlans == nil || a.decision == nil || a.verifier == nil {
		return false, ErrAdministrativeSourceUnconfirmed
	}
	if a.budgetBound && a.budget == nil {
		return false, ErrAdministrativeSourceUnconfirmed
	}
	at := a.decision()
	if at.IsZero() {
		return false, ErrAdministrativeSourceUnconfirmed
	}
	// Условия читают тот же post-wait момент; caller context не меняется.
	cond := administrativeContext(input, at)
	in := Query{PreparedPlans: a.preparedPlans, DecisionAt: at, Subject: subject, ObjectType: typ, ObjectID: id, Relation: relation, Context: cond}
	v, g, err := askAdministrativeBound(ctx, a.transaction, in, a.verifier, a.boundary, a.budget, a.bound)
	a.observe(g)
	return v == Allow, err
}

// Каждая страница содержит точные ключи, а не свёрнутые условия. Иначе живой
// альтернативный держатель оказался бы неотличим от истёкшего. Keyset включает
// condition JSON, сортируется COLLATE C и не зависит от порядка выдачи строк.
func administrativeQuerySQL(labelTable string, nesting bool) (string, error) {
	sql, err := verdictQuerySQL(labelTable, nesting)
	if err != nil {
		return "", err
	}
	replacements := [][2]string{
		{"rs.arm AS arm", "rs.arm AS arm, ''::text AS object_type, ''::text AS object_id, ''::text AS relation, ''::text AS subject"},
		{"''::text AS arm\n      FROM kaname.relation_fact f", "''::text AS arm, f.object_type, f.object_id, f.relation, f.subject\n      FROM kaname.relation_fact f"},
		{"SELECT src.cond_name, src.cond_params, src.arm FROM (", "SELECT src.cond_name, src.cond_params, src.arm, src.object_type, src.object_id, src.relation, src.subject, src.cond_params::text FROM ("},
		{"b.expires_at > now()", "b.expires_at > $13::timestamptz"},
		{") src\nLIMIT $8::int", ") src\nWHERE (src.object_type COLLATE \"C\",src.object_id COLLATE \"C\",src.relation COLLATE \"C\",src.subject COLLATE \"C\",src.cond_name COLLATE \"C\",src.cond_params::text COLLATE \"C\") > ($14::text COLLATE \"C\",$15::text COLLATE \"C\",$16::text COLLATE \"C\",$17::text COLLATE \"C\",$18::text COLLATE \"C\",$19::text COLLATE \"C\")\nORDER BY src.object_type COLLATE \"C\",src.object_id COLLATE \"C\",src.relation COLLATE \"C\",src.subject COLLATE \"C\",src.cond_name COLLATE \"C\",src.cond_params::text COLLATE \"C\"\nLIMIT $8::int"},
	}
	for _, r := range replacements {
		sql, err = replaceOnce(sql, r[0], r[1])
		if err != nil {
			return "", err
		}
	}
	return sql, nil
}
func askAdministrative(ctx context.Context, tx pgx.Tx, in Query, verify AdministrativeVerifier) (Verdict, Grounds, error) {
	return askAdministrativeBound(ctx, tx, in, verify, nil, nil, false)
}
func askAdministrativeBound(ctx context.Context, tx pgx.Tx, in Query, verify AdministrativeVerifier, boundary AdministrativeReadBoundary, budget *AdministrativeReadBudget, bound bool) (Verdict, Grounds, error) {
	var g Grounds
	if err := ctx.Err(); err != nil {
		return Unknown, g, err
	}
	if in.Subject == "" || in.ObjectType == "" || in.ObjectID == "" || in.Relation == "" || in.DecisionAt.IsZero() {
		return Unknown, g, ErrAdministrativeSourceUnconfirmed
	}
	var scopes []AdministrativeScope
	global := false
	if bound {
		if boundary == nil || budget == nil {
			return Unknown, g, ErrAdministrativeSourceUnconfirmed
		}
		var err error
		scopes, global, err = boundary.NativeScopes(in.Subject, in.ObjectType, in.ObjectID, in.Relation)
		if err != nil {
			return Unknown, g, err
		}
	}
	// Переданный бюджет, с boundary или без него, уже оплатил
	// existence/admission в pg wrapper. Исторические unbound callers сохраняют
	// отдельный бюджет на вопрос и прежнее списание трёх чтений.
	cost := 1
	if budget == nil {
		budget = &AdministrativeReadBudget{}
		cost = 3
	}
	if err := budget.Charge(cost, cost); err != nil {
		return Unknown, g, err
	}
	parents, relations, verbs, err := sourcesOfPrepared(in.PreparedPlans, in.ObjectType, in.Relation)
	if err != nil {
		if errors.Is(err, authzplan.ErrTypeNotDeclared) && !isGrantCapabilityType(in.ObjectType) {
			g.TypeNotDeclared = true
			return Deny, g, nil
		}
		return Unknown, g, err
	}
	if isGrantCapabilityType(in.ObjectType) {
		return askGrantCapability(ctx, tx, in)
	}
	cat, nesting, err := catalogTypeName(ctx, tx, in.ObjectType)
	if err != nil {
		return Unknown, g, err
	}
	labels, err := labelAxisOf(cat, in.ObjectType)
	if err != nil {
		return Unknown, g, err
	}
	g.LabelAxisTable = labels
	sql, err := administrativeQuerySQL(labels, nesting)
	if err != nil {
		return Unknown, g, err
	}
	var scopeJSON []byte
	if bound && !global {
		sql, scopeJSON, err = capturedAdministrativeSQL(sql, in.ObjectType, in.ObjectID, scopes)
		if err != nil {
			return Unknown, g, err
		}
	}
	var cursor [6]string
	var unknown error
	for {
		if err = ctx.Err(); err != nil {
			return Unknown, g, err
		}
		if err = budget.Charge(0, 1); err != nil {
			return Unknown, g, err
		}
		args := []any{in.Subject, in.ObjectType, in.ObjectID, parents, relations, verbs, MaxAncestorDepth, 256, cat, classSlot(in.Subject, 0), classSlot(in.Subject, 1), hierarchy.MaxImmediateParents, in.DecisionAt, cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5]}
		if bound && !global {
			args = append(args, scopeJSON)
		}
		rows, e := tx.Query(ctx, sql, args...)
		if e != nil {
			return Unknown, g, e
		}
		type candidate struct {
			fact     AdministrativeFact
			arm, raw string
		}
		page := make([]candidate, 0, 256)
		for rows.Next() {
			var c candidate
			if e = rows.Scan(&c.fact.ConditionName, &c.fact.ConditionParameters, &c.arm, &c.fact.ObjectType, &c.fact.ObjectID, &c.fact.Relation, &c.fact.Subject, &c.raw); e != nil {
				break
			}
			page = append(page, c)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return Unknown, g, e
		}
		if err = budget.Charge(len(page), 0); err != nil {
			return Unknown, g, err
		}
		for _, c := range page {
			if err = ctx.Err(); err != nil {
				return Unknown, g, err
			}
			c.fact.QuestionRelation = in.Relation
			ok, e := checkAdministrativeCandidate(ctx, c.fact, in.Context, budget, verify)
			var unknownCondition errUnknownCondition
			if errors.Is(e, ErrAdministrativeSourceUnconfirmed) || errors.As(e, &unknownCondition) {
				unknown = e
				continue
			}
			if e != nil {
				return Unknown, g, e
			}
			if !ok {
				continue
			}
			if err = ctx.Err(); err != nil {
				return Unknown, g, err
			}
			if c.arm == "labels" {
				g.LabelArm = true
			}
			return Allow, g, nil
		}
		if len(page) < 256 {
			g.SetExhausted = true
			if unknown != nil {
				return Unknown, g, unknown
			}
			return Deny, g, nil
		}
		last := page[len(page)-1]
		next := [6]string{last.fact.ObjectType, last.fact.ObjectID, last.fact.Relation, last.fact.Subject, last.fact.ConditionName, last.raw}
		if next == cursor {
			return Unknown, g, fmt.Errorf("%w: non-progressing cursor", ErrAdministrativeSourceUnconfirmed)
		}
		cursor = next
	}
}

func administrativeContext(input map[string]any, at time.Time) map[string]any {
	out := make(map[string]any, len(input)+1)
	for key, value := range input {
		out[key] = value
	}
	out["current_time"] = at
	return out
}

// Известное ложное условие исключает leaf до проверки происхождения: его
// provenance не влияет на union и не отравляет отдельный живой v_list.
// Неизвестное условие остаётся unknown; удовлетворённое условие НЕ освобождает
// от проверки точного source. Caller передаёт defensive context с DecisionAt.
func checkAdministrativeCandidate(ctx context.Context, fact AdministrativeFact, conditions map[string]any, budget *AdministrativeReadBudget, verify AdministrativeVerifier) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if fact.ConditionName != "" {
		ok, err := evalCondition(fact.ConditionName, fact.ConditionParameters, conditions)
		if err != nil || !ok {
			return false, err
		}
	}
	return verify(ctx, fact, budget)
}
