// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Capability обязательна на новых producer точках; отсутствие откатывает TX.
// Старый порт чтения scopes не превращается в публичный writer API.
type producerReceiptStore interface {
	SaveProducerReceiptTx(context.Context, service.Tx, domain.ProducerReceipt) error
	InvalidateRegistrationReceiptsTx(context.Context, service.Tx, string, time.Time, string) error
}

func (uc *RegisterResourceUseCase) saveProducerReceipt(ctx context.Context, tx service.Tx, kind, module, catalogType string, t tupleIntent, scopes []domain.ContainerScope, version time.Time) error {
	store, ok := uc.scopes.(producerReceiptStore)
	if !ok {
		return proxyWriteRefusal()
	}
	typ, id := t.splitObject()
	subjectType, subjectID, ok := strings.Cut(t.subject, ":")
	if !ok {
		return proxyWriteRefusal()
	}
	r := domain.ProducerReceipt{Kind: kind, Module: module, CatalogType: catalogType, ObjectType: typ, ObjectID: id, Relation: t.relation, Subject: domain.Subject{Type: domain.SubjectType(subjectType), ID: domain.SubjectID(subjectID)}, Scopes: scopes, SourceVersion: version}
	if err := r.Validate(); err != nil {
		return err
	}
	return store.SaveProducerReceiptTx(ctx, tx, r)
}
func (uc *RegisterResourceUseCase) invalidateRegistrationReceipts(ctx context.Context, tx service.Tx, object string, version time.Time, reason string) error {
	store, ok := uc.scopes.(producerReceiptStore)
	if !ok {
		return proxyWriteRefusal()
	}
	return store.InvalidateRegistrationReceiptsTx(ctx, tx, object, version, reason)
}
