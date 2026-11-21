// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Пустое событие ReconcileObject линеаризуется в исходном master RR snapshot.
// Это не authority decision: нет RC, manifest, final clock или body writes.
// Будущий producer обслуживается собственным co-committed reconcile event.
// Частично удалённый объект, неизвестный источник и ошибка бюджета не no-op.
func (p *resourceObjectPreparation) emptySnapshot(ctx context.Context, parents *resourceParentCapture) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if p == nil || p.source == nil || p.root == nil || p.lifetime == nil || parents == nil || parents.source != p.source ||
		p.source.lifetime != p.lifetime || p.source.sealed || p.lifetime.ended || p.lifetime.prepared != nil ||
		parents.tx == nil || parents.tx != p.source.stageTX || parents.tx.Conn() != p.lifetime.conn {
		return false, kaname.ErrSourceUnconfirmed
	}
	// Исключение принадлежит только полному ReconcileObject, не регистрации и
	// не добавляющим forward/NoStale маршрутам.
	if p.route != resourceObjectFull {
		return false, nil
	}
	if !nativeQuestionToken(p.root.object.Type) || !nativeQuestionToken(p.root.object.ID) || !nativeQuestionToken(p.root.modelType) {
		return false, kaname.ErrSourceUnconfirmed
	}
	kind := resourceSourceMirror
	if domain.FeedSourceForType(p.root.object.Type) == domain.FeedIAMDirect {
		kind = resourceSourceIAMObject
	}
	objectKey := resourceSourceKey{kind: kind, typ: p.root.object.Type, id: p.root.object.ID}
	objectRows, captured := p.source.entries[objectKey]
	if !captured {
		return false, kaname.ErrSourceUnconfirmed
	}
	if len(objectRows) != 0 {
		return false, nil
	}
	if len(p.outputs) != 1 || p.outputs[0] != p.root || len(p.inputs) != 0 || len(p.commands) != 0 ||
		len(p.root.bindings) != 0 || len(p.root.roles) != 0 || len(p.root.selected) != 0 {
		return false, nil
	}
	// captureResourceOutput уже читает восемь predicates holders. Требуем именно наличие
	// каждого завершённого capture, а не отсутствие map entry вместо пустоты.
	for _, k := range []resourceSourceKind{resourceSourcePointerFacts, resourceSourceObjectReceipts, resourceSourceObjectPublication,
		resourceSourceObjectRetirement, resourceSourceRegistrationPointers, resourceSourceObjectMembers, resourceSourceObjectLedger, resourceSourceFactLedgerHolders} {
		typ := p.root.modelType
		if k == resourceSourceObjectMembers || k == resourceSourceObjectLedger {
			typ = p.root.object.Type
		}
		rows, ok := p.source.entries[resourceSourceKey{kind: k, typ: typ, id: p.root.object.ID}]
		if !ok {
			return false, kaname.ErrSourceUnconfirmed
		}
		if len(rows) != 0 {
			return false, nil
		}
	}
	if p.root.modelType == "cluster" {
		rows, ok := p.source.entries[resourceSourceKey{kind: resourceSourceClusterFactHolders, typ: "cluster", id: p.root.object.ID}]
		if !ok {
			return false, kaname.ErrSourceUnconfirmed
		}
		if len(rows) != 0 {
			return false, nil
		}
	}
	// Отсутствующая mirror строка сама не доказывает отсутствие удержанных
	// проекций и parent edges. Эти exact predicates читаются в том же RR.
	for _, k := range []resourceSourceKind{resourceSourceParentEdges, resourceSourceDescendantEdges, resourceSourceRegistrationScopes, resourceSourceProjectBinding} {
		rows, err := p.source.read(ctx, parents.tx, resourceSourceKey{kind: k, typ: p.root.modelType, id: p.root.object.ID})
		if err != nil {
			return false, err
		}
		if len(rows) != 0 {
			return false, nil
		}
	}
	return true, ctx.Err()
}
