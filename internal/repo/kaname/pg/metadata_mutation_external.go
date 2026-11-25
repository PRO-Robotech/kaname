// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

type mirrorMetadataScope struct {
	account string
	project string
}

func (r metadataMutation) catalogType() string {
	if r.table != "resource_mirror" {
		return r.nativeCatalogType()
	}
	// IAM использует свои таблицы и порты. Внешний тип всегда задаётся
	// канонической парой module.resource и затем разрешается в снимке БД.
	if strings.HasPrefix(r.kind, "iam.") {
		return ""
	}
	if _, ok := metadataBindingRoot(r.kind); !ok {
		return ""
	}
	return r.kind
}

func (r metadataMutation) catalogRef() domain.ResourceRef {
	return domain.ResourceRef{Type: r.catalogType(), ID: r.id}
}

// Старое состояние, модельный тип, действие и область относятся к одному
// RR-снимку. Идентификаторы владения не принимаются из запроса клиента.
func (s *metadataStage) readMirrorRoot(ctx context.Context, tx pgx.Tx) (mirrorMetadataScope, error) {
	var scope mirrorMetadataScope
	err := tx.QueryRow(ctx, `
 SELECT m.xmin::text,to_jsonb(m),c.object_type,
        coalesce(nullif(m.parent_account_id,''),p.account_id),coalesce(p.id,'')
 FROM ONLY kaname.resource_mirror m
 JOIN ONLY kaname.catalog_resource c ON c.dotted=m.object_type AND c.live AND c.module<>'iam'
 JOIN ONLY kaname.catalog_verb v ON (v.module,v.resource)=(c.module,c.resource)
  AND v.live AND v.per_object AND v.verb='update'
 LEFT JOIN ONLY kaname.projects p ON p.id=nullif(m.parent_project_id,'')
 WHERE m.object_type=$1 AND m.object_id=$2
  AND (nullif(m.parent_account_id,'') IS NOT NULL OR p.account_id IS NOT NULL)
  AND (nullif(m.parent_project_id,'') IS NULL OR
   (p.id IS NOT NULL AND (nullif(m.parent_account_id,'') IS NULL OR m.parent_account_id=p.account_id)))`,
		s.request.kind, s.request.id).Scan(&s.xmin, &s.old, &s.request.typ, &scope.account, &scope.project)
	if errors.Is(err, pgx.ErrNoRows) {
		return mirrorMetadataScope{}, iamerr.ErrPermissionDenied
	}
	if err != nil {
		return mirrorMetadataScope{}, err
	}
	if !nativeQuestionToken(s.request.typ) || grantcapability.IsInternalObjectType(s.request.typ) ||
		!nativeQuestionToken(scope.account) || (scope.project != "" && !nativeQuestionToken(scope.project)) {
		return mirrorMetadataScope{}, kaname.ErrSourceUnconfirmed
	}
	return scope, nil
}

// При отсутствии маски protobuf map не различает пустую карту и пропуск.
// Явная маска, напротив, допускает очистку выбранного пространства.
func mirrorMetadataRequest(root domain.ResourceRef, labels, accessLabels domain.Labels, mask []string) metadataMutation {
	fields := slices.Clone(mask)
	if len(fields) == 0 {
		if len(labels) != 0 {
			fields = append(fields, "labels")
		}
		if len(accessLabels) != 0 {
			fields = append(fields, "access_labels")
		}
	}
	mode := metadataMutationOrdinary
	if slices.Contains(fields, "access_labels") {
		mode = metadataMutationAccessLabels
	}
	return metadataMutation{kind: root.Type, table: "resource_mirror", id: root.ID, mode: mode,
		labels: maps.Clone(labels), accessLabels: maps.Clone(accessLabels), mask: fields}
}

// Внешний runtime-порт подключается отдельно после проверки контракта БД.
// При конфликте повторяем всю попытку с новым RR, включая авторизацию и
// резерв обеих записей outbox. Результат отдаём только после commit.
func (p *MetadataMutationWriters) updateMirrorAccessLabels(ctx context.Context, root domain.ResourceRef,
	labels, accessLabels domain.Labels, mask []string, actor domain.Subject,
) (domain.ResourceMetadata, error) {
	return p.writeMirrorMetadata(ctx, mirrorMetadataRequest(root, labels, accessLabels, mask), actor)
}

func (p *MetadataMutationWriters) writeMirrorMetadata(ctx context.Context, request metadataMutation, actor domain.Subject) (domain.ResourceMetadata, error) {
	root := request.catalogRef()
	if request.table != "resource_mirror" || root.Type == "" {
		return domain.ResourceMetadata{}, kaname.ErrInvalidAuthorityFencePlan
	}
	if slices.Contains(request.mask, "labels") {
		if err := request.labels.Validate(); err != nil {
			return domain.ResourceMetadata{}, err
		}
	}
	var result domain.ResourceMetadata
	mirrorWork := metadataProtectedWorkLimit
	err := executePreparedAttempts(ctx, func(ctx context.Context) (*metadataWriteTx, error) {
		return p.openMetadataTx(ctx, request, actor, &mirrorWork)
	}, func(ctx context.Context, tx *metadataWriteTx) error {
		command := tx.protected
		if command == nil || command.root != root || len(command.mirrorOld) == 0 {
			return kaname.ErrSourceUnconfirmed
		}
		if _, err := command.ordinaryMask(request); err != nil {
			return err
		}
		// Владелец проверяет утверждённую команду, сам выполняет UPDATE и
		// обе записи outbox. PostgreSQL сравнивает возвращённую строку
		// целиком с ожидаемым NEW, включая поля вне пользовательской маски.
		var actual domain.ResourceMetadata
		err := tx.tx.QueryRow(ctx, `WITH applied AS MATERIALIZED (
 SELECT kaname.authority_metadata_mirror_apply_v1($1,$2) AS obj
)
SELECT obj->>'object_type',obj->>'object_id',obj->'labels',obj->'access_labels'
 FROM applied WHERE obj=($3::jsonb || $4::jsonb)
 AND obj->>'object_type'=$1 AND obj->>'object_id'=$2 AND (NOT $5::boolean OR obj=$3::jsonb)`,
			root.Type, root.ID, command.mirrorOld, command.patch, len(tx.changed) == 0).
			Scan(&actual.ResourceType, &actual.ResourceID, &actual.Labels, &actual.AccessLabels)
		if errors.Is(err, pgx.ErrNoRows) {
			return kaname.ErrSourceUnconfirmed
		}
		if err != nil {
			return mapProtectedMetadataErr(err)
		}
		if request.operation != nil {
			if err := request.operation.finish(ctx, tx.tx, tx.mirrorAccount, actual); err != nil {
				return err
			}
		}
		result = actual
		return nil
	})
	if err != nil {
		return domain.ResourceMetadata{}, err
	}
	return result, nil
}
