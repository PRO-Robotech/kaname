// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/service"
)

const externalMetadataGet = `
	SELECT r.object_type, statement_timestamp()
	  FROM kaname.catalog_resource r
	  JOIN kaname.catalog_verb v ON (v.module, v.resource) = (r.module, r.resource)
	 WHERE r.dotted = $1 AND r.live AND r.module <> 'iam'
	   AND v.live AND v.per_object AND v.verb = 'get'`

// ResourceMetadataRepo читает метки внешнего ресурса после штатной проверки
// объектного права get. Для ресурсов IAM действуют их собственные обработчики.
type ResourceMetadataRepo struct {
	primary *pgxpool.Pool
	plans   *authzmodel.Plans
}

func NewResourceMetadataRepo(primary *pgxpool.Pool, plans *authzmodel.Plans) *ResourceMetadataRepo {
	return &ResourceMetadataRepo{primary: primary, plans: plans}
}

func (r *ResourceMetadataRepo) ReadAuthorizedMirrorMetadata(
	ctx context.Context, subject, dottedType, objectID string,
) (domain.ResourceMetadata, error) {
	var out domain.ResourceMetadata
	module, resource, dotted := strings.Cut(dottedType, ".")
	if !dotted || module == "" || resource == "" || strings.Contains(resource, ".") || strings.TrimSpace(objectID) == "" {
		return out, iamerr.Wrapf(iamerr.ErrInvalidArg, "resourceType and resourceId are required; use a module.resource type")
	}
	if r.primary == nil || r.plans == nil {
		return out, iamerr.ErrUnavailable
	}

	// Каталог, основания доступа и зеркало читаются с ведущей БД на одном снимке.
	// Отдельное чтение после решения могло бы вернуть уже перерегистрированный объект.
	tx, err := r.primary.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, fmt.Errorf("%w: открыть снимок метаданных: %w", iamerr.ErrUnavailable, err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()

	var modelType string
	var decisionAt time.Time
	err = tx.QueryRow(ctx, externalMetadataGet, dottedType).Scan(&modelType, &decisionAt)
	if errors.Is(err, pgx.ErrNoRows) || grantcapability.IsInternalObjectType(modelType) {
		return out, iamerr.ErrPermissionDenied
	}
	if err != nil {
		return out, fmt.Errorf("%w: прочитать тип и действие метаданных: %w", iamerr.ErrUnavailable, err)
	}
	// Надзор администратора действует только для координаты, для которой у
	// допущенной модели есть объектный план чтения.
	const relation = "v_get"
	if !r.plans.Declares(modelType, relation) {
		return out, iamerr.ErrUnavailable
	}
	verdict := authzcascade.WrapAdmitted(relverdict.NewTransactionAsker(tx, r.plans, decisionAt), personmarks.NewTransaction(tx))
	checker := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           verdict,
		ClusterAdminChecker: verdict,
		Now:                 func() time.Time { return decisionAt },
	})
	result, err := checker.CheckRelation(ctx, service.CheckRelationRequest{
		Subject: subject, Relation: relation, Object: modelType + ":" + objectID,
	})
	if err != nil {
		return out, fmt.Errorf("%w: проверить чтение метаданных: %w", iamerr.ErrUnavailable, err)
	}
	if !result.Allowed {
		return out, iamerr.ErrPermissionDenied
	}

	row, found, err := resource_mirror.GetByObject(ctx, tx, dottedType, objectID)
	if err != nil {
		return out, fmt.Errorf("%w: прочитать зеркало ресурса: %w", iamerr.ErrUnavailable, err)
	}
	if !found {
		return out, iamerr.ErrNotFound
	}
	if row.ParentProjectID != "" {
		var scopeMatches bool
		err = tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT FROM kaname.projects WHERE id = $1 AND account_id = $2
		)`, row.ParentProjectID, row.ParentAccountID).Scan(&scopeMatches)
		if err != nil {
			return out, fmt.Errorf("%w: проверить область метаданных: %w", iamerr.ErrUnavailable, err)
		}
		if !scopeMatches {
			return out, iamerr.ErrUnavailable
		}
	}
	return domain.ResourceMetadata{
		ResourceType: row.ObjectType, ResourceID: row.ObjectID,
		Labels: row.Labels, AccessLabels: row.AccessLabels,
	}, nil
}
