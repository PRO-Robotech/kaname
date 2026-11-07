// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/corelib/platformmodules"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RegistrationAccountWriterStore доступен только установке; публичные административные RPC
// не открывают ни этот писатель, ни его узкое переопределение защиты удаления.
type RegistrationAccountWriterStore struct{ pool *pgxpool.Pool }

func NewRegistrationAccountWriterStore(pool *pgxpool.Pool) *RegistrationAccountWriterStore {
	return &RegistrationAccountWriterStore{pool: pool}
}

type writerAssignment struct {
	id, account, module, binding string
	removed                      bool
}

func (r *RegistrationAccountWriterStore) ApplyRegistrationAccountWriters(ctx context.Context, plan seed.RegistrationWriterPlan) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Сериализуем полные планы параллельных стартов HA до чтения их журнала.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('kaname.registration_account_writer_plan',0))`); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT assignment_id,account_id,module,binding_id,removed_at IS NOT NULL FROM kaname.registration_account_writer_assignment ORDER BY assignment_id`)
	if err != nil {
		return err
	}
	previous, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (writerAssignment, error) {
		var a writerAssignment
		e := row.Scan(&a.id, &a.account, &a.module, &a.binding, &a.removed)
		return a, e
	})
	if err != nil {
		return err
	}
	byID := map[string]writerAssignment{}
	for _, a := range previous {
		byID[a.id] = a
	}
	desired := map[string]bool{}
	pairs := map[string]bool{}
	var problems []string
	for _, a := range plan.Assignments {
		desired[a.AssignmentID] = true
		pairs[a.AccountID+"/"+a.Module] = true
		if old, ok := byID[a.AssignmentID]; ok && (old.account != a.AccountID || old.module != a.Module) {
			problems = append(problems, "assignment identity changed: "+a.AssignmentID)
		}
		var account, sa bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.accounts WHERE id=$1),EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$2)`, a.AccountID, authzguard.ServiceAccountIDForService(a.Module)).Scan(&account, &sa)
		if err != nil {
			return err
		}
		if !account || !sa {
			problems = append(problems, "missing account/module SA: "+a.AccountID+"/"+a.Module)
		}
	}
	var switched bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.registration_account_writer_switch)`).Scan(&switched); err != nil {
		return err
	}
	if !switched {
		disabled := map[string]bool{}
		for _, d := range plan.Disabled {
			disabled[d.AccountID+"/"+d.Module] = true
		}
		// Учитываем канонические проект/аккаунт и модуль-владелец из каталога, а не
		// parent_account_id запроса. Неопределённые существующие строки тоже сообщаются.
		rows, err = tx.Query(ctx, `SELECT DISTINCT coalesce(s.account_id,''),split_part(c.dotted,'.',1)
 FROM kaname.resource_mirror m JOIN kaname.catalog_resource c ON c.dotted=m.object_type
 LEFT JOIN LATERAL kaname.registration_legacy_scopes(c.object_type,m.object_id) s ON true
 WHERE split_part(c.dotted,'.',1)<>'iam' ORDER BY 1,2`)
		if err != nil {
			return err
		}
		census, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) ([2]string, error) {
			var p [2]string
			e := row.Scan(&p[0], &p[1])
			return p, e
		})
		if err != nil {
			return err
		}
		for _, p := range census {
			module := p[1]
			if service, ok := platformmodules.ServiceOfCatalogModule(module); ok {
				module = service
			}
			key := p[0] + "/" + module
			if p[0] == "" || (!pairs[key] && !disabled[key]) {
				problems = append(problems, "existing registration needs assignment or explicit disabled exception: "+key)
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("registration-account-writers preflight: %s", strings.Join(problems, "; "))
	}
	// Все проверки завершены до любой записи состояния доступа.
	for _, a := range previous {
		if !desired[a.id] && !a.removed {
			if err := revokeRegistrationWriter(ctx, tx, a); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE kaname.registration_account_writer_assignment SET removed_at=clock_timestamp() WHERE assignment_id=$1`, a.id); err != nil {
				return err
			}
		}
	}
	for _, a := range plan.Assignments {
		if _, seen := byID[a.AssignmentID]; seen {
			continue
		} // отозвано/удалено — окончательное состояние
		binding := domain.AccessBindingID("acb" + domain.DerivedIDSuffix("registration-account-writer:"+a.AssignmentID))
		subject := domain.SubjectID(authzguard.ServiceAccountIDForService(a.Module))
		w := &abWriter{abReader: abReader{tx: tx}}
		created, err := w.Insert(ctx, domain.AccessBinding{ID: binding, SubjectType: domain.SubjectTypeServiceAccount, SubjectID: subject, ResourceType: domain.ResourceType("account"), ResourceID: a.AccountID, Status: domain.AccessBindingStatusActive, GrantedRelation: authzguard.RelationWriteRelation, System: true, DeletionProtection: true})
		if err != nil {
			return err
		}
		if err = w.InsertSubjects(ctx, binding, []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: subject}}); err != nil {
			return err
		}
		tuples := []ab.RelationTuple{{User: "service_account:" + string(subject), Relation: authzguard.RelationWriteRelation, Object: "account:" + a.AccountID}}
		parent, ok := created.StructuralParent()
		if !ok {
			return fmt.Errorf("registration writer binding has no structural parent")
		}
		tuples = append(tuples, ab.RelationTuple{User: parent.User, Relation: parent.Relation, Object: parent.Object})

		if err = w.InsertEmittedTuples(ctx, binding, tuples); err != nil {
			return err
		}
		if err = w.EmitRelationWrite(ctx, tuples); err != nil {
			return err
		}
		if err = (&writeTx{readTx: readTx{tx: tx}}).EmitReconcileEvent(ctx, "mirror.upsert", "iam.accessBinding", string(binding)); err != nil {
			return err
		}
		if err = registrationWriterEvent(ctx, w, "granted", string(binding), a.AccountID, string(subject)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO kaname.registration_account_writer_assignment(assignment_id,account_id,module,binding_id) VALUES($1,$2,$3,$4)`, a.AssignmentID, a.AccountID, a.Module, string(binding)); err != nil {
			return err
		}
	}
	if !switched {
		disabled, err := json.Marshal(plan.Disabled)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO kaname.registration_account_writer_switch(singleton,disabled_modules) VALUES(true,$1::jsonb)`, disabled); err != nil {
			return err
		}
	}
	if plan.RetireClusterWriter {
		if err := retireClusterRegistrationWriter(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Это существующий защищённый жизненный цикл: рекомендательная блокировка, FOR UPDATE,
// снятие защиты только с координат, принадлежащих журналу, защищённый отзыв,
// снятие точного записанного набора, изменение субъекта и аудит в ТОЙ ЖЕ транзакции.
func revokeRegistrationWriter(ctx context.Context, tx pgx.Tx, a writerAssignment) error {
	wtx := &writeTx{readTx: readTx{tx: tx}}
	if err := wtx.AdvisoryXactLock(ctx, a.binding); err != nil {
		return err
	}
	w := wtx.AccessBindingsW()
	b, err := w.GetForDeactivation(ctx, domain.AccessBindingID(a.binding))
	if errors.Is(err, iamerr.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !b.System || b.ResourceType != domain.ResourceType("account") || b.ResourceID != a.account || string(b.SubjectID) != authzguard.ServiceAccountIDForService(a.module) || b.GrantedRelation != authzguard.RelationWriteRelation || b.RoleID != "" {
		return fmt.Errorf("registration writer ledger does not own binding %s", a.binding)
	}
	subjects, err := wtx.AccessBindings().ListSubjects(ctx, b.ID)
	if err != nil {
		return err
	}
	if len(subjects) != 1 || subjects[0].Type != b.SubjectType || subjects[0].ID != b.SubjectID {
		return fmt.Errorf("registration writer binding subjects changed")
	}
	if b.Status != domain.AccessBindingStatusActive {
		return nil
	}
	if _, err = w.SetDeletionProtection(ctx, b.ID, false); err != nil {
		return err
	}
	if _, err = w.RevokeGuarded(ctx, b.ID, domain.UserID("system:registration-account-writers")); err != nil {
		return err
	}
	stored, err := wtx.AccessBindings().SelectEmittedTuples(ctx, b.ID)
	if err != nil {
		return err
	}
	if err = w.EmitRelationDelete(ctx, stored); err != nil {
		return err
	}
	return registrationWriterEvent(ctx, w, "revoked", a.binding, a.account, string(b.SubjectID))
}

func registrationWriterEvent(ctx context.Context, w ab.WriterIface, action, binding, account, subject string) error {
	if err := w.EmitSubjectChangeEvent(ctx, ab.SubjectChangeEvent{SubjectType: "service_account", SubjectID: subject, EventType: map[string]string{"granted": "binding_grant", "revoked": "binding_revoke"}[action], Op: map[string]string{"granted": "binding_upsert", "revoked": "binding_delete"}[action]}); err != nil {
		return err
	}
	return w.EmitAuditEvent(ctx, ab.AuditEvent{EventType: ab.AuditEventType("iam.access_binding." + action), Actor: "system:registration-account-writers", SubjectType: "service_account", SubjectID: subject, ResourceType: "account", ResourceID: account, BindingID: binding, TenantAccountID: account})
}

// retireClusterRegistrationWriter — односторонний переход установки после того,
// как оператор закрыл вход на старые реплики. Не выводит выдачи аккаунтов
// из общей выдачи и не меняет публичных правил защиты удаления.
func retireClusterRegistrationWriter(ctx context.Context, tx pgx.Tx) error {
	// Та же старая блокировка пространства имён начального наполнения удерживается совместно при UPSERT группы
	// и выдаче. Исключительный режим закрывает оба порядка, не полагаясь на уже существующую
	// строку переключения или изменяемые имена для определения принадлежности назначения.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('kaname.registration_legacy_writer_seed',0))`); err != nil {
		return err
	}
	var recreated bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM kaname.registration_legacy_cluster_writer_identity i
 JOIN kaname.groups g ON g.account_id=i.account_id AND g.name=i.original_seed_name
 WHERE i.singleton AND g.id<>i.group_id)`).Scan(&recreated); err != nil {
		return err
	}
	if recreated {
		return fmt.Errorf("legacy writer seed namespace was recreated; resolve its group before retirement")
	}
	rows, err := tx.Query(ctx, `SELECT b.id FROM kaname.access_bindings b
 WHERE kaname.registration_owns_legacy_cluster_writer(b) AND b.status='ACTIVE' ORDER BY b.id`)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	wtx := &writeTx{readTx: readTx{tx: tx}}
	for _, id := range ids {
		if err = wtx.AdvisoryXactLock(ctx, id); err != nil {
			return err
		}
		w := wtx.AccessBindingsW()
		b, err := w.GetForDeactivation(ctx, domain.AccessBindingID(id))
		if err != nil {
			return err
		}
		var owned bool
		if err = tx.QueryRow(ctx, `SELECT kaname.registration_owns_legacy_cluster_writer(b) FROM kaname.access_bindings b WHERE b.id=$1`, id).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return fmt.Errorf("legacy writer binding ownership changed")
		}

		if b.Status != domain.AccessBindingStatusActive {
			continue
		}
		if _, err = w.SetDeletionProtection(ctx, b.ID, false); err != nil {
			return err
		}
		if _, err = w.RevokeGuarded(ctx, b.ID, "system:registration-account-writers"); err != nil {
			return err
		}
		stored, err := wtx.AccessBindings().SelectEmittedTuples(ctx, b.ID)
		if err != nil {
			return err
		}
		if err = w.EmitRelationDelete(ctx, stored); err != nil {
			return err
		}
		if err = w.EmitSubjectChangeEvent(ctx, ab.SubjectChangeEvent{SubjectType: "group", SubjectID: string(b.SubjectID), EventType: "binding_revoke", Op: "binding_delete"}); err != nil {
			return err
		}
		if err = w.EmitAuditEvent(ctx, ab.AuditEvent{EventType: ab.AuditEventTypeRevoked, Actor: "system:registration-account-writers", SubjectType: "group", SubjectID: string(b.SubjectID), ResourceType: "cluster", ResourceID: b.ResourceID, BindingID: id}); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE kaname.registration_account_writer_switch SET cluster_writer_retired_at=coalesce(cluster_writer_retired_at,clock_timestamp()) WHERE singleton`)
	return err
}
