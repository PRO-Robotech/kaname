// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

type metadataMutationMode uint8

const (
	metadataMutationOrdinary metadataMutationMode = iota
	metadataMutationAccessLabels
)

// Указатели сохраняют пустые строки, а отдельные JSON-карты отличают очистку
// от пропуска поля. Порядок полей совпадает с прежним кодированием patch-карты.
type metadataMutationPatch struct {
	AccessLabels json.RawMessage `json:"access_labels,omitempty"`
	Description  *string         `json:"description,omitempty"`
	Labels       json.RawMessage `json:"labels,omitempty"`
	Name         *string         `json:"name,omitempty"`
}

func prepareMetadataMutationPatch(request metadataMutation) (metadataMutationPatch, error) {
	var patch metadataMutationPatch
	if request.catalogType() == "" {
		return patch, kaname.ErrInvalidAuthorityFencePlan
	}
	switch request.mode {
	case metadataMutationOrdinary:
		if slices.Contains(request.mask, "access_labels") {
			return patch, kaname.ErrInvalidAuthorityFencePlan
		}
	case metadataMutationAccessLabels:
		if !slices.Contains(request.mask, "access_labels") {
			return patch, kaname.ErrInvalidAuthorityFencePlan
		}
	default:
		return patch, kaname.ErrInvalidAuthorityFencePlan
	}
	fields := request.mask
	if len(fields) == 0 && request.table != "resource_mirror" {
		// Пустая обычная маска выбирает три прежних поля. Защищённая правка
		// всегда называет своё поле явно.
		fields = []string{"name", "description", "labels"}
	}
	for _, field := range fields {
		switch field {
		case "name":
			if request.table == "resource_mirror" {
				return metadataMutationPatch{}, kaname.ErrInvalidAuthorityFencePlan
			}
			patch.Name = &request.name
		case "description":
			if request.table == "resource_mirror" {
				return metadataMutationPatch{}, kaname.ErrInvalidAuthorityFencePlan
			}
			patch.Description = &request.description
		case "labels":
			encoded, err := marshalLabels(request.labels)
			if err != nil {
				return metadataMutationPatch{}, err
			}
			patch.Labels = json.RawMessage(encoded)
		case "access_labels":
			if err := request.accessLabels.Validate(); err != nil {
				return metadataMutationPatch{}, err
			}
			encoded, err := marshalLabels(request.accessLabels)
			if err != nil {
				return metadataMutationPatch{}, err
			}
			patch.AccessLabels = json.RawMessage(encoded)
		default:
			return metadataMutationPatch{}, kaname.ErrInvalidAuthorityFencePlan
		}
	}
	return patch, nil
}

type metadataPreflightResult struct {
	RowXmin  string
	RowValue json.RawMessage
}

func (s *metadataStage) preflight(ctx context.Context, tx pgx.Tx, actor domain.Subject, patch []byte, staged bool) (metadataPreflightResult, error) {
	var result metadataPreflightResult
	if s == nil || s.plan == nil || s.plan.nativeBudget == nil || actor.Validate() != nil {
		return result, kaname.ErrInvalidAuthorityFencePlan
	}
	request := s.request
	if err := chargeNativePolicyBudget(s.plan.nativeBudget, 4, 23); err != nil {
		return result, err
	}
	var query string
	switch {
	case staged:
		query = `SELECT row_xmin,row_value FROM kaname.authority_metadata_preflight_staged_v1($1,$2,$3,$4,$5::jsonb)`
	case s.grant != nil:
		query = `SELECT row_xmin,row_value FROM kaname.authority_metadata_preflight_v5($1,$2,$3,$4,$5::jsonb)`
	default:
		query = `SELECT row_xmin,row_value FROM kaname.authority_metadata_preflight_v4($1,$2,$3,$4,$5::jsonb)`
	}
	err := tx.QueryRow(ctx, query, request.kind, request.id, s.rename, string(s.auditID), patch).Scan(&result.RowXmin, &result.RowValue)
	return result, err
}
