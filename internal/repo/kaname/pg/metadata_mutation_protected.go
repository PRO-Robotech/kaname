// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/jackc/pgx/v5/pgconn"
)

// metadataMutationPorts позволяет сохранить прежние маршруты, пока
// миграция защищённой записи ещё не подтверждена в выбранной БД.
type metadataMutationPorts interface {
	kaname.AccountMetadataWriterFactory
	kaname.ProjectMetadataWriterFactory
	kaname.ServiceAccountMetadataWriterFactory
}

const (
	metadataAccessLabelReadiness = "kaname.authority_metadata_access_label_ready_v2(text)"
	metadataAccessLabelClientABI = "metadata-access-label/owner-retention-v2"
)

type accessLabelMetadataWriters struct{ *MetadataMutationWriters }

// Отдельная обёртка не объявляет SA capability до подтверждения её SQL контракта.
type serviceAccountAccessLabelMetadataWriters struct{ *accessLabelMetadataWriters }

const serviceAccountAccessLabelReadiness = "kaname.authority_metadata_service_account_access_label_ready_v1()"

// WithInstalledAccessLabels добавляет защищённые порты только при подтверждённом
// контракте БД. Во время поэтапной установки та же служба принимает обычные маски.
func (p *MetadataMutationWriters) WithInstalledAccessLabels(ctx context.Context) (metadataMutationPorts, error) {
	if p == nil || p.policy == nil || p.policy.repo == nil {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	pool := p.policy.repo.master
	var installed, ready bool
	if err := pool.QueryRow(ctx, `SELECT pg_catalog.to_regprocedure($1) IS NOT NULL`, metadataAccessLabelReadiness).Scan(&installed); err != nil {
		return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	if !installed {
		return p, nil
	}
	if err := pool.QueryRow(ctx, `SELECT kaname.authority_metadata_access_label_ready_v2($1)`, metadataAccessLabelClientABI).Scan(&ready); err != nil {
		return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	if !ready {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	base := &accessLabelMetadataWriters{p}
	if err := pool.QueryRow(ctx, `SELECT pg_catalog.to_regprocedure($1) IS NOT NULL`, serviceAccountAccessLabelReadiness).Scan(&installed); err != nil {
		return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	if !installed {
		return base, nil
	}
	if err := pool.QueryRow(ctx, `SELECT kaname.authority_metadata_service_account_access_label_ready_v1()`).Scan(&ready); err != nil {
		return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	if !ready {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	return &serviceAccountAccessLabelMetadataWriters{base}, nil
}

func (p *accessLabelMetadataWriters) AccountAccessLabelsWriter(ctx context.Context, value domain.Account, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, metadataMutation{kind: "account", table: "accounts", typ: "account", id: string(value.ID),
		name: string(value.Name), description: string(value.Description), labels: value.Labels, accessLabels: value.AccessLabels,
		mode: metadataMutationAccessLabels, mask: slices.Clone(mask)}, actor)
}

func (p *accessLabelMetadataWriters) ProjectAccessLabelsWriter(ctx context.Context, value domain.Project, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, metadataMutation{kind: "project", table: "projects", typ: "project", id: string(value.ID),
		name: string(value.Name), description: string(value.Description), labels: value.Labels, accessLabels: value.AccessLabels,
		mode: metadataMutationAccessLabels, mask: slices.Clone(mask)}, actor)
}

func (p *serviceAccountAccessLabelMetadataWriters) ServiceAccountAccessLabelsWriter(ctx context.Context, value domain.ServiceAccount, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, metadataMutation{kind: "service_account", table: "service_accounts", typ: "iam_service_account", id: string(value.ID),
		name: string(value.Name), description: string(value.Description), labels: value.Labels, accessLabels: value.AccessLabels,
		mode: metadataMutationAccessLabels, mask: slices.Clone(mask)}, actor)
}

var _ kaname.ServiceAccountAccessLabelsWriterFactory = (*serviceAccountAccessLabelMetadataWriters)(nil)
var _ kaname.AccountAccessLabelsWriterFactory = (*accessLabelMetadataWriters)(nil)
var _ kaname.ProjectAccessLabelsWriterFactory = (*accessLabelMetadataWriters)(nil)

// Команда относится к одному ресурсу и одной подготовленной попытке.
// Значения для защищённого UPDATE берутся только из закрытой программы БД.
type metadataProtectedWrite struct {
	root         domain.ResourceRef
	mirrorOld    json.RawMessage
	patch        []byte
	changesLabel bool
}

func (c *metadataProtectedWrite) ordinaryMask(request metadataMutation) ([]string, error) {
	if c.root != request.catalogRef() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	patch, err := prepareMetadataMutationPatch(request)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, c.patch) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return slices.DeleteFunc(slices.Clone(request.mask), func(field string) bool { return field == "access_labels" }), nil
}

func (w *metadataWriteTx) AccountsW() account.WriterIface {
	writer := w.semanticAuthorityWriteTx.AccountsW()
	if w.protected == nil {
		return writer
	}
	return &protectedAccountMetadata{WriterIface: writer, tx: w}
}

func (w *metadataWriteTx) ProjectsW() project.WriterIface {
	writer := w.semanticAuthorityWriteTx.ProjectsW()
	if w.protected == nil {
		return writer
	}
	return &protectedProjectMetadata{WriterIface: writer, tx: w}
}

func (w *metadataWriteTx) ServiceAccountsW() service_account.WriterIface {
	writer := w.semanticAuthorityWriteTx.ServiceAccountsW()
	if w.protected == nil {
		return writer
	}
	return &protectedServiceAccountMetadata{WriterIface: writer, tx: w}
}

type protectedAccountMetadata struct {
	account.WriterIface
	tx *metadataWriteTx
}

func (w *protectedAccountMetadata) Update(ctx context.Context, value domain.Account, mask []string) (domain.Account, error) {
	regular, err := w.tx.protected.ordinaryMask(metadataMutation{
		kind: "account", table: "accounts", typ: "account", id: string(value.ID), mode: metadataMutationAccessLabels,
		name: string(value.Name), description: string(value.Description), labels: value.Labels, accessLabels: value.AccessLabels, mask: mask,
	})
	if err != nil {
		return domain.Account{}, err
	}
	if w.tx.protected.changesLabel {
		row := w.tx.tx.QueryRow(ctx, `SELECT `+accountCols+`
 FROM jsonb_populate_record(NULL::kaname.accounts,kaname.authority_metadata_access_label_write_v1('account',$1))`, value.ID)
		out, err := scanAccount(row)
		if err != nil {
			return domain.Account{}, mapErr(err, "Account.Update", string(value.Name))
		}
		return out, nil
	}
	if len(regular) == 0 {
		// Пустая обычная маска означает полную правку. При одинаковых
		// accessLabels и отсутствии других полей достаточно вернуть строку.
		return w.tx.Accounts().Get(ctx, value.ID)
	}
	return w.WriterIface.Update(ctx, value, regular)
}

type protectedProjectMetadata struct {
	project.WriterIface
	tx *metadataWriteTx
}

func (w *protectedProjectMetadata) Update(ctx context.Context, value domain.Project, mask []string) (domain.Project, error) {
	regular, err := w.tx.protected.ordinaryMask(metadataMutation{
		kind: "project", table: "projects", typ: "project", id: string(value.ID), mode: metadataMutationAccessLabels,
		name: string(value.Name), description: string(value.Description), labels: value.Labels, accessLabels: value.AccessLabels, mask: mask,
	})
	if err != nil {
		return domain.Project{}, err
	}
	if w.tx.protected.changesLabel {
		row := w.tx.tx.QueryRow(ctx, `SELECT `+projectCols+`
 FROM jsonb_populate_record(NULL::kaname.projects,kaname.authority_metadata_access_label_write_v1('project',$1))`, value.ID)
		out, err := scanProject(row)
		if err != nil {
			return domain.Project{}, mapErr(err, "Project.Update", string(value.Name))
		}
		return out, nil
	}
	if len(regular) == 0 {
		return w.tx.Projects().Get(ctx, value.ID)
	}
	return w.WriterIface.Update(ctx, value, regular)
}

type protectedServiceAccountMetadata struct {
	service_account.WriterIface
	tx *metadataWriteTx
}

func (w *protectedServiceAccountMetadata) Update(ctx context.Context, value domain.ServiceAccount, mask []string) (domain.ServiceAccount, error) {
	regular, err := w.tx.protected.ordinaryMask(metadataMutation{
		kind: "service_account", table: "service_accounts", typ: "iam_service_account", id: string(value.ID), mode: metadataMutationAccessLabels,
		name: string(value.Name), description: string(value.Description), labels: value.Labels, accessLabels: value.AccessLabels, mask: mask,
	})
	if err != nil {
		return domain.ServiceAccount{}, err
	}
	if w.tx.protected.changesLabel {
		row := w.tx.tx.QueryRow(ctx, `SELECT `+saCols+`
 FROM jsonb_populate_record(NULL::kaname.service_accounts,kaname.authority_metadata_access_label_write_v1('service_account',$1))`, value.ID)
		out, err := scanSA(row)
		if err != nil {
			return domain.ServiceAccount{}, mapErr(err, "ServiceAccount.Update", string(value.Name))
		}
		return out, nil
	}
	if len(regular) == 0 {
		return w.tx.ServiceAccounts().Get(ctx, value.ID)
	}
	return w.WriterIface.Update(ctx, value, regular)
}

func (s *metadataStage) approveProtectedApply(ctx context.Context, w *semanticAuthorityWriteTx, work *int) error {
	actor := s.plan.request.actor
	if s.request.kind == "group" {
		return s.acceptGroupProtected(ctx, w.tx, actor, work)
	}
	budget := s.plan.nativeBudget
	var cost protectedMetadataCost
	err := w.tx.QueryRow(ctx, `SELECT used_rows,used_reads,used_work
 FROM kaname.authority_metadata_access_label_accept_v2($1,$2,$3,$4,$5)`,
		string(actor.Type), string(actor.ID), budget.RemainingRows(), budget.RemainingReads(), *work).
		Scan(&cost.Rows, &cost.Reads, &cost.Work)
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	return s.chargeProtected(cost, work)
}

func mapProtectedMetadataErr(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "42501":
		return iamerr.Wrapf(iamerr.ErrPermissionDenied, "Access label apply authority denied")
	case "54000":
		return errors.Join(kaname.ErrSourceReadLimit, err)
	default:
		return err
	}
}
