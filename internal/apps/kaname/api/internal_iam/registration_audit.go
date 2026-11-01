// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// registrationHierarchy читает родителя по политике и фактам kaname. Субъект
// нового указателя допустим только после admitRegistration; при снятии и отказе
// читаются стоящие указатели, а присланные поля области не используются.
func (uc *RegisterResourceUseCase) registrationHierarchy(ctx context.Context, tx service.Tx, t tupleIntent, admittedWrite bool) (domain.ParentHierarchy, error) {
	typ, id := t.splitObject()
	_, policy, live, err := uc.catalogTypes.WritePolicyTx(ctx, tx, typ)
	if err != nil || !live {
		return domain.ParentHierarchy{}, err
	}
	var anchors []string
	if _, pointer := policy.Pointer(t.relation); admittedWrite && pointer {
		anchors = []string{t.subject}
	} else {
		anchors, err = uc.scopes.PointerSubjectsTx(ctx, tx, typ, id, policy.PointerNames())
		if err != nil {
			return domain.ParentHierarchy{}, err
		}
	}
	for _, anchor := range anchors {
		h, ok, err := uc.hierarchyOf(ctx, tx, anchor)
		if err != nil {
			return domain.ParentHierarchy{}, err
		}
		if ok {
			return h, nil
		}
	}
	return domain.ParentHierarchy{}, nil
}

// hierarchyAuditFields не заполняет отсутствующее значение словом вызывающего.
func hierarchyAuditFields(h domain.ParentHierarchy) map[string]any {
	p := map[string]any{"parent_chain": h.Links}
	if len(h.Links) > 0 {
		typ, id, _ := strings.Cut(h.Links[0], ":")
		p["parent"] = map[string]any{"type": typ, "id": id}
	}
	return p
}

// RecordRefusal сохраняет исход отдельной транзакцией после отката изменения.
// Сбой аудита возвращается обработчику: отказ не объявляется записанным, пока
// его событие не зафиксировано. Прямой вызов use-case отказов не записывает.
func (uc *RegisterResourceUseCase) RecordRefusal(ctx context.Context, in unregisterInput, unregister bool, outcome string) error {
	if _, _, verified := authzguard.ModuleActor(ctx); !verified {
		return nil
	}
	t := tupleIntent{subject: in.GetSubjectId(), relation: in.GetRelation(), object: in.GetObject()}
	typ, id := t.splitObject()
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin registration refusal audit: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	catalogType, err := uc.catalogObjectType(ctx, tx, typ)
	if err != nil {
		return fmt.Errorf("resolve refusal audit type: %w", err)
	}
	h, err := uc.registrationHierarchy(ctx, tx, t, false)
	if err != nil {
		return fmt.Errorf("read refusal audit hierarchy: %w", err)
	}
	eventType := AuditEventResourceRegistered
	if unregister {
		eventType = AuditEventResourceUnregistered
	}
	event := auditEvent(ctx, eventType, outcome, t, service.ResourceMirrorRow{
		ObjectType: catalogType, ObjectID: id, SourceVersion: sourceVersion(in), ParentAccountID: h.AccountID,
	}, hierarchyAuditFields(h))
	if err := uc.audit.EmitTx(ctx, tx, event); err != nil {
		return fmt.Errorf("emit refusal audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit refusal audit: %w", err)
	}
	return nil
}
