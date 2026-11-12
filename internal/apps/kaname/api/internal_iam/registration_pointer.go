// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// registrationPointerStore хранит доказательство ранее допущенной регистрации.
// Текущий каталог и стоящий факт по отдельности таким доказательством не являются.
type registrationPointerStore interface {
	SaveRegistrationPointerTx(context.Context, service.Tx, string, service.RelationTuple, time.Time) (bool, error)
	RegistrationPointersTx(context.Context, service.Tx, string, string) ([]service.RelationTuple, error)
	RetireRegistrationPointersTx(context.Context, service.Tx, string, string, time.Time) error
	PrepareRegistrationWithdrawalTx(context.Context, service.Tx, string, string, time.Time) (bool, bool, error)
	RetireDescendantRegistrationPointersTx(context.Context, service.Tx, string, string, time.Time) ([]service.VersionedRelationTuple, error)
}

func legacyRegistrationRelation(relation string) bool {
	return proxytuple.Hierarchical(proxytuple.Relation(relation))
}

func containsRegistrationTuple(tuples []service.RelationTuple, want service.RelationTuple) bool {
	for _, have := range tuples {
		if have == want {
			return true
		}
	}
	return false
}

func (uc *RegisterResourceUseCase) registrationPointers(ctx context.Context, tx service.Tx, catalogType, object string) ([]service.RelationTuple, error) {
	store, ok := uc.scopes.(registrationPointerStore)
	if !ok {
		// Старые адаптеры обслуживают только прежний closed-three. Вход нового
		// указателя без обязательного хранилища отдельно отвергается при записи.
		return nil, nil
	}
	owner, ok := catalogModule(catalogType)
	if !ok {
		return nil, proxyWriteRefusal()
	}
	return store.RegistrationPointersTx(ctx, tx, owner, object)
}

func (uc *RegisterResourceUseCase) retireRegistrationPointers(ctx context.Context, tx service.Tx, catalogType, object string, version time.Time, tuples []service.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	store, ok := uc.scopes.(registrationPointerStore)
	if !ok {
		return proxyWriteRefusal()
	}
	owner, ok := catalogModule(catalogType)
	if !ok {
		return proxyWriteRefusal()
	}
	return store.RetireRegistrationPointersTx(ctx, tx, owner, object, version)
}

// namedPointerSubjectType — общий предел формы родителя до чтения каталога
// и при допуске точного указателя. Проект допустим; принципалы и вершины IAM — нет.
func namedPointerSubjectType(typ string) bool {
	if internalGrantReference(typ) {
		return false
	}
	if typ == "project" {
		return true
	}
	for _, forbidden := range proxytuple.ForbiddenObjectTypes() {
		if typ == forbidden {
			return false
		}
	}
	return typ != "" && !strings.Contains(typ, "*")
}

// versionedWithdrawalEmitter — обязательная capability named/mixed пути.
// Её отсутствие откатывает всю TX; два старых emit не являются заменой.
type versionedWithdrawalEmitter interface {
	EmitVersionedDeleteTx(context.Context, service.Tx, []service.VersionedRelationTuple) error
}

func (uc *RegisterResourceUseCase) prepareRegistrationWithdrawal(ctx context.Context, tx service.Tx, catalogType, object string, version time.Time) (bool, error) {
	store, ok := uc.scopes.(registrationPointerStore)
	if !ok {
		return false, nil
	}
	owner, ok := catalogModule(catalogType)
	if !ok {
		return false, proxyWriteRefusal()
	}
	allowed, active, err := store.PrepareRegistrationWithdrawalTx(ctx, tx, owner, object, version)
	if err != nil {
		return false, err
	}
	if !allowed {
		return false, proxyWriteRefusal()
	}
	return active, nil
}

func (uc *RegisterResourceUseCase) retireDescendantPointers(ctx context.Context, tx service.Tx, catalogType, object string, version time.Time, owned []service.RelationTuple) ([]service.VersionedRelationTuple, error) {
	if len(owned) == 0 {
		return nil, nil
	}
	store, ok := uc.scopes.(registrationPointerStore)
	if !ok {
		return nil, proxyWriteRefusal()
	}
	owner, ok := catalogModule(catalogType)
	if !ok {
		return nil, proxyWriteRefusal()
	}
	return store.RetireDescendantRegistrationPointersTx(ctx, tx, owner, object, version)
}

func (uc *RegisterResourceUseCase) emitWithdrawalSet(ctx context.Context, tx service.Tx, tuples []service.RelationTuple, version time.Time, gone []droppedDescendant, named, deleted bool) error {
	for _, d := range gone {
		named = named || len(d.ownedDeletes) > 0
	}
	if !named {
		return uc.emitter.EmitOrderedDeleteTx(ctx, tx, tuples, version)
	}
	emitter, ok := uc.emitter.(versionedWithdrawalEmitter)
	if !ok {
		return proxyWriteRefusal()
	}
	rows := make([]service.VersionedRelationTuple, 0, len(tuples))
	for _, t := range tuples {
		rows = append(rows, service.VersionedRelationTuple{Tuple: t, SourceVersion: version, CurrentRemoval: version.IsZero() && deleted})
	}
	for i := range gone {
		d := &gone[i]
		legacyVersion := version
		if d.version.After(legacyVersion) {
			legacyVersion = d.version
		}
		// Явное намерение без версии принадлежит текущему root действию, а не max(P,C).
		// Только реально снятый legacy потомок использует unversioned journal
		// и точный action-bounded receipt; named own C/mode ниже не меняются.
		if version.IsZero() && d.dropped {
			legacyVersion = time.Time{}
		}
		for _, t := range proxyOwned(d.Standing) {
			rows = append(rows, service.VersionedRelationTuple{Tuple: t, SourceVersion: legacyVersion, CurrentRemoval: version.IsZero() && d.dropped})
		}
		rows = append(rows, d.ownedDeletes...)
		d.factsEmitted = true
	}
	return emitter.EmitVersionedDeleteTx(ctx, tx, rows)
}
