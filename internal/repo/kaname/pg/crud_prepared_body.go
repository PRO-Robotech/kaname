// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepp "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	accountrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	projectrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	sarepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type crudStepValues struct {
	Kind string          `json:"kind"`
	IDs  []int64         `json:"ids"`
	Row  json.RawMessage `json:"row"`
}
type preparedCRUDWriter struct {
	*semanticAuthorityWriteTx
	lifetime      *resourceAttemptLifetime
	transactionAt time.Time
}

func newPreparedCRUDWriter(ctx context.Context, w *semanticAuthorityWriteTx, lifetime *resourceAttemptLifetime, intent json.RawMessage) (*preparedCRUDWriter, error) {
	if w == nil || !lifetime.valid(w.authorityWriteTx, w.bundle) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var admitted bool
	if err := w.tx.QueryRow(ctx, `SELECT kaname.authority_resource_assert_body_v2($1::jsonb)`, intent).Scan(&admitted); err != nil {
		return nil, err
	}
	if !admitted {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var values struct {
		TransactionAt time.Time `json:"transaction_at"`
		DecisionAt    time.Time `json:"decision_at"`
	}
	var raw []byte
	if err := w.tx.QueryRow(ctx, `SELECT kaname.authority_resource_crud_body_values_v3()`).Scan(&raw); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	if values.TransactionAt.IsZero() || !values.DecisionAt.Equal(lifetime.at) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return &preparedCRUDWriter{semanticAuthorityWriteTx: w, lifetime: lifetime, transactionAt: values.TransactionAt}, nil
}
func (w *preparedCRUDWriter) claim(ctx context.Context, kind string, request any) (crudStepValues, error) {
	var step crudStepValues
	if w == nil || !w.lifetime.valid(w.authorityWriteTx, w.bundle) {
		return step, kaname.ErrSourceUnconfirmed
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return step, err
	}
	var raw []byte
	if err = w.tx.QueryRow(ctx, `SELECT kaname.authority_resource_crud_step_v3($1,$2::jsonb)`, kind, encoded).Scan(&raw); err != nil {
		return step, err
	}
	if err = json.Unmarshal(raw, &step); err != nil {
		return step, err
	}
	if step.Kind != kind {
		return step, kaname.ErrSourceUnconfirmed
	}
	return step, ctx.Err()
}
func (w *preparedCRUDWriter) Commit(ctx context.Context) error {
	if w == nil || !w.lifetime.valid(w.authorityWriteTx, w.bundle) {
		return kaname.ErrSourceUnconfirmed
	}
	w.lifetime.close()
	// Deferred completion в private manifest проверяет все обязательные эффекты.
	return w.semanticAuthorityWriteTx.Commit(ctx)
}
func (w *preparedCRUDWriter) Rollback(ctx context.Context) error {
	if w == nil {
		return kaname.ErrSourceUnconfirmed
	}
	w.lifetime.close()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return w.semanticAuthorityWriteTx.Rollback(cleanup)
}
func (w *preparedCRUDWriter) AdvisoryXactLock(ctx context.Context, key string) error {
	if w == nil || !w.lifetime.valid(w.authorityWriteTx, w.bundle) {
		return kaname.ErrSourceUnconfirmed
	}
	// После final clock отсутствующий legacy lock только отвергается, не приобретается.
	_, err := w.tx.Exec(ctx, `SELECT kaname.authority_resource_crud_lock_held_v3($1)`, key)
	return err
}
func (w *preparedCRUDWriter) AccountsW() accountrepo.WriterIface {
	return &crudAccountBody{accountWriter: &accountWriter{accountReader: accountReader{tx: w.tx}, ownerFKHintSink: &w.ownerFKHint}, w: w}
}
func (w *preparedCRUDWriter) ProjectsW() projectrepo.WriterIface {
	return &crudProjectBody{projectWriter: &projectWriter{projectReader: projectReader{tx: w.tx}}, w: w}
}
func (w *preparedCRUDWriter) ServiceAccountsW() sarepo.WriterIface {
	return &crudServiceAccountBody{saWriter: &saWriter{saReader: saReader{tx: w.tx}}, w: w}
}
func (w *preparedCRUDWriter) RolesW() rolerepo.WriterIface {
	return &crudRoleBody{roleWriter: &roleWriter{roleReader: roleReader{tx: w.tx}}, w: w}
}
func (w *preparedCRUDWriter) AccessBindingsW() abrepp.WriterIface {
	return &crudBindingBody{abWriter: &abWriter{abReader: abReader{tx: w.tx}}, w: w}
}

type crudAccountBody struct {
	*accountWriter
	w *preparedCRUDWriter
}

func (b *crudAccountBody) Insert(ctx context.Context, a domain.Account) (domain.Account, error) {
	if _, err := b.w.claim(ctx, "account.insert", a); err != nil {
		return domain.Account{}, err
	}
	out, err := b.accountWriter.insertAt(ctx, a, b.w.transactionAt)
	if err != nil {
		return domain.Account{}, err
	}
	// Deferred quota/admission входят в ту же закрытую команду, а не в следующий
	// шаг. Все их physical locks уже удержаны до единственного final clock.
	if _, err = b.w.tx.Exec(ctx, `SET CONSTRAINTS kaname.accounts_quota_count, kaname.accounts_rate_admission IMMEDIATE`); err != nil {
		return domain.Account{}, mapErr(err, "Account.Create", string(a.ID))
	}
	if _, err = b.w.tx.Exec(ctx, `SET CONSTRAINTS kaname.accounts_quota_count, kaname.accounts_rate_admission DEFERRED`); err != nil {
		return domain.Account{}, err
	}
	return out, nil
}
func (b *crudAccountBody) Delete(ctx context.Context, id domain.AccountID) error {
	if _, err := b.w.claim(ctx, "account.delete", id); err != nil {
		return err
	}
	if err := b.accountWriter.Delete(ctx, id); err != nil {
		return err
	}
	if _, err := b.w.tx.Exec(ctx, `SET CONSTRAINTS kaname.accounts_quota_count IMMEDIATE`); err != nil {
		return mapErr(err, "Account.Delete", string(id))
	}
	_, err := b.w.tx.Exec(ctx, `SET CONSTRAINTS kaname.accounts_quota_count DEFERRED`)
	return err
}

type crudProjectBody struct {
	*projectWriter
	w *preparedCRUDWriter
}

func (b *crudProjectBody) Insert(ctx context.Context, p domain.Project) (domain.Project, error) {
	if _, err := b.w.claim(ctx, "project.insert", p); err != nil {
		return domain.Project{}, err
	}
	return b.projectWriter.insertAt(ctx, p, b.w.transactionAt)
}
func (b *crudProjectBody) Delete(ctx context.Context, id domain.ProjectID) error {
	if _, err := b.w.claim(ctx, "project.delete", id); err != nil {
		return err
	}
	return b.projectWriter.Delete(ctx, id)
}

type crudServiceAccountBody struct {
	*saWriter
	w *preparedCRUDWriter
}

func (b *crudServiceAccountBody) Insert(ctx context.Context, s domain.ServiceAccount) (domain.ServiceAccount, error) {
	if _, err := b.w.claim(ctx, "service_account.insert", s); err != nil {
		return domain.ServiceAccount{}, err
	}
	return b.saWriter.insertAt(ctx, s, b.w.transactionAt)
}
func (b *crudServiceAccountBody) Delete(ctx context.Context, id domain.ServiceAccountID) error {
	if _, err := b.w.claim(ctx, "service_account.delete", id); err != nil {
		return err
	}
	return b.saWriter.Delete(ctx, id)
}

type crudRoleBody struct {
	*roleWriter
	w *preparedCRUDWriter
}

func (b *crudRoleBody) Delete(ctx context.Context, id domain.RoleID) error {
	if _, err := b.w.claim(ctx, "role.delete", id); err != nil {
		return err
	}
	return b.roleWriter.Delete(ctx, id)
}

type crudBindingBody struct {
	*abWriter
	w *preparedCRUDWriter
}

func (b *crudBindingBody) Insert(ctx context.Context, a domain.AccessBinding) (domain.AccessBinding, error) {
	if _, err := b.w.claim(ctx, "binding.insert", a.ID); err != nil {
		return domain.AccessBinding{}, err
	}
	return b.abWriter.insertAt(ctx, a, &b.w.transactionAt)
}
func (b *crudBindingBody) Delete(ctx context.Context, id domain.AccessBindingID) error {
	if _, err := b.w.claim(ctx, "binding.delete", id); err != nil {
		return err
	}
	return b.abWriter.Delete(ctx, id)
}
func (b *crudBindingBody) InsertSubjects(ctx context.Context, id domain.AccessBindingID, subjects []domain.Subject) error {
	if _, err := b.w.claim(ctx, "binding.subjects", struct {
		ID       domain.AccessBindingID
		Subjects []domain.Subject
	}{id, subjects}); err != nil {
		return err
	}
	return b.abWriter.InsertSubjects(ctx, id, subjects)
}
func (b *crudBindingBody) InsertEmittedTuples(ctx context.Context, id domain.AccessBindingID, tuples []abrepp.RelationTuple) error {
	if _, err := b.w.claim(ctx, "binding.ledger", struct {
		ID     domain.AccessBindingID
		Tuples []abrepp.RelationTuple
	}{id, tuples}); err != nil {
		return err
	}
	return b.abWriter.InsertEmittedTuples(ctx, id, tuples)
}
func (b *crudBindingBody) EmitAuditEvent(ctx context.Context, event abrepp.AuditEvent) error {
	step, err := b.w.claim(ctx, "binding.audit", event)
	if err != nil {
		return err
	}
	return b.w.insertPreparedAudit(ctx, step.Row)
}
func (w *preparedCRUDWriter) EmitAuditEvent(ctx context.Context, event service.AuditEvent) error {
	step, err := w.claim(ctx, "audit", event)
	if err != nil {
		return err
	}
	return w.insertPreparedAudit(ctx, step.Row)
}
func (w *preparedCRUDWriter) insertPreparedAudit(ctx context.Context, row json.RawMessage) error {
	var a resourceObjectAuditValue
	if err := json.Unmarshal(row, &a.Row); err != nil {
		return err
	}
	if a.Row.ID == "" || !a.Row.CreatedAt.Equal(w.transactionAt) || !a.Row.NextAttemptAt.Equal(w.transactionAt) {
		return kaname.ErrSourceUnconfirmed
	}
	_, err := w.tx.Exec(ctx, `INSERT INTO kaname.audit_outbox(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at)
VALUES($1,$2,$3,$4::jsonb,'pending',0,$5,$6)`, a.Row.ID, a.Row.EventType, a.Row.TenantAccountID, a.Row.Payload, a.Row.CreatedAt, a.Row.NextAttemptAt)
	return err
}
func (w *preparedCRUDWriter) EmitReconcileEvent(ctx context.Context, eventType, objectType, objectID string) error {
	request := struct {
		EventType  string
		ObjectType string
		ObjectID   string
	}{eventType, objectType, objectID}
	step, err := w.claim(ctx, "reconcile", request)
	if err != nil {
		return err
	}
	var row struct {
		ID         int64     `json:"id"`
		EventType  string    `json:"event_type"`
		ObjectType string    `json:"object_type"`
		ObjectID   string    `json:"object_id"`
		CreatedAt  time.Time `json:"created_at"`
	}
	if err = json.Unmarshal(step.Row, &row); err != nil {
		return err
	}
	if row.ID <= 0 || row.EventType != eventType || row.ObjectType != objectType || row.ObjectID != objectID || !row.CreatedAt.Equal(w.transactionAt) {
		return kaname.ErrSourceUnconfirmed
	}
	_, err = w.tx.Exec(ctx, `INSERT INTO kaname.resource_reconcile_outbox(id,event_type,object_type,object_id,created_at,attempt_count)
OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,0)`, row.ID, row.EventType, row.ObjectType, row.ObjectID, row.CreatedAt)
	return err
}
func (w *preparedCRUDWriter) EmitFGARelationWrite(ctx context.Context, tuples []service.RelationTuple) error {
	return w.emitPreparedRelations(ctx, fga_outbox.EventTypeWrite, tuples)
}
func (w *preparedCRUDWriter) EmitFGARelationDelete(ctx context.Context, tuples []service.RelationTuple) error {
	return w.emitPreparedRelations(ctx, fga_outbox.EventTypeDelete, tuples)
}
func (w *preparedCRUDWriter) emitPreparedRelations(ctx context.Context, kind string, tuples []service.RelationTuple) error {
	step, err := w.claim(ctx, kind, tuples)
	if err != nil {
		return err
	}
	at := w.transactionAt
	if kind == fga_outbox.EventTypeDelete {
		at = w.lifetime.at
	}
	return fga_outbox.EmitReservedDecisionTx(ctx, w.tx, kind, serviceTuplesToClients(tuples), at, step.IDs)
}

var _ kaname.SemanticAuthorityWriter = (*preparedCRUDWriter)(nil)
