// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// SaveProducerReceiptTx вызывается после applied producer outcome, до коммита.
// Модуль приходит из admission; текущая строка каталога лишь проверяет его,
// а не подставляется вместо происхождения исторического источника.
func (RegistrationScopeReader) SaveProducerReceiptTx(ctx context.Context, tx service.Tx, r domain.ProducerReceipt) error {
	if err := r.Validate(); err != nil {
		return err
	}
	ptx := txAsPgx(tx)
	var owned bool
	if err := ptx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.catalog_resource WHERE dotted=$1 AND object_type=$2 AND module=$3)`, r.CatalogType, r.ObjectType, r.Module).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return domain.ErrProducerReceipt
	}
	// Области перепроверяются, но не выводятся заново из клиентского утверждения.
	for _, s := range r.Scopes {
		var matches bool
		if err := ptx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.accounts a WHERE a.id=$1 AND ($2::text='' OR EXISTS(SELECT 1 FROM kaname.projects p WHERE p.id=$2 AND p.account_id=a.id)))`, s.AccountID, s.ProjectID).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return domain.ErrProducerReceipt
		}
	}
	if _, err := ptx.Exec(ctx, `UPDATE kaname.producer_source_receipt SET active=false,invalidation='module_replaced',model_identity=NULL,catalog_identity=NULL,projector_version=NULL WHERE kind=$1 AND object_type=$2 AND object_id=$3 AND module<>$4`, r.Kind, r.ObjectType, r.ObjectID, r.Module); err != nil {
		return err
	}
	scopes, err := json.Marshal(r.Scopes)
	if err != nil {
		return err
	}
	// Publication version берётся из применившегося intent: zero withdrawal
	// сохраняет ordered watermark. Неприменившийся replay сюда не поступает.
	version := ownerVersionOrMinusInfinity(r.SourceVersion)
	if r.Kind == domain.PublicationReceipt {
		var published bool
		if err := ptx.QueryRow(ctx, `SELECT source_version,published FROM kaname.public_read_publication WHERE object_type=$1 AND object_id=$2`, r.ObjectType, r.ObjectID).Scan(&version, &published); err != nil {
			return err
		}
		if !published {
			return domain.ErrProducerReceipt
		}
	}
	_, err = ptx.Exec(ctx, `INSERT INTO kaname.producer_source_receipt(kind,module,catalog_type,object_type,object_id,relation,subject_type,subject_id,condition_name,condition_parameters,scopes,source_version,versionless,active)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,true)
 ON CONFLICT(kind,module,object_type,object_id,relation,subject_type,subject_id) DO UPDATE SET catalog_type=EXCLUDED.catalog_type,scopes=EXCLUDED.scopes,source_version=greatest(producer_source_receipt.source_version,EXCLUDED.source_version),versionless=EXCLUDED.versionless,active=true,invalidation='',model_identity=NULL,catalog_identity=NULL,projector_version=NULL`, r.Kind, r.Module, r.CatalogType, r.ObjectType, r.ObjectID, r.Relation, string(r.Subject.Type), string(r.Subject.ID), r.ConditionName, r.ConditionParameters, scopes, version, r.SourceVersion.IsZero())
	if err != nil {
		return fmt.Errorf("save producer receipt: %w", err)
	}
	return nil
}

// InvalidateRegistrationReceiptsTx исполняется только после применившегося
// удаления либо замены проекции. Повтор/старое надгробие его не вызывает.
// Владелец потомка берётся из сохранённой receipt, не из модуля родителя.
func (RegistrationScopeReader) InvalidateRegistrationReceiptsTx(ctx context.Context, tx service.Tx, object string, version time.Time, reason string) error {
	typ, id, ok := strings.Cut(object, ":")
	if !ok || typ == "" || id == "" || (reason != "withdrawn" && reason != "projection_replaced") {
		return domain.ErrProducerReceipt
	}
	_, err := txAsPgx(tx).Exec(ctx, `UPDATE kaname.producer_source_receipt SET active=false,invalidation=$3,source_version=greatest(source_version,$4::timestamptz),model_identity=NULL,catalog_identity=NULL,projector_version=NULL WHERE kind='registration_owner' AND object_type=$1 AND object_id=$2`, typ, id, reason, ownerVersionOrMinusInfinity(version))
	return err
}
