// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type resourceGenerationProjection struct {
	fingerprint   *string
	outputRefs    []string
	externalRoots []domain.ResourceRef
}

// Читаем только координаты и хеш в том же RR, что отбор носителей.
// Хеш служит для сравнения снимков, разрешение на закрытие выдаёт владелец SQL.
func captureResourceGeneration(ctx context.Context, parents *resourceParentCapture, model, id string) (resourceGenerationProjection, error) {
	budget := parents.source.budget
	remaining := budget.RemainingReads()
	if remaining == 0 {
		return resourceGenerationProjection{}, kaname.ErrSourceReadLimit
	}
	var fingerprint *string
	var roots, outputs [][]string
	var rows, reads int
	err := parents.tx.QueryRow(ctx, `SELECT fingerprint,roots,outputs,logical_rows,logical_reads
 FROM kaname.authority_resource_generation_observe_v1($1,$2,$3,$4)`,
		model, id, budget.RemainingRows(), remaining).Scan(&fingerprint, &roots, &outputs, &rows, &reads)
	if err != nil {
		return resourceGenerationProjection{}, resourceOpenError(ctx, err)
	}
	if reads < 1 {
		return resourceGenerationProjection{}, kaname.ErrSourceUnconfirmed
	}
	if err = chargeNativePolicyBudget(budget, rows, reads); err != nil {
		return resourceGenerationProjection{}, err
	}
	if roots == nil || outputs == nil {
		return resourceGenerationProjection{}, kaname.ErrSourceUnconfirmed
	}
	if fingerprint == nil {
		if len(roots) != 0 || len(outputs) != 0 {
			return resourceGenerationProjection{}, kaname.ErrSourceUnconfirmed
		}
		return resourceGenerationProjection{}, nil
	}
	hash, err := hex.DecodeString(*fingerprint)
	if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != *fingerprint || len(roots) == 0 {
		return resourceGenerationProjection{}, kaname.ErrSourceUnconfirmed
	}
	if len(roots) > rows || len(outputs) > rows {
		return resourceGenerationProjection{}, kaname.ErrSourceUnconfirmed
	}
	out := resourceGenerationProjection{fingerprint: fingerprint, outputRefs: make([]string, 0, len(outputs))}
	for _, root := range roots {
		if len(root) != 2 || !nativeQuestionToken(root[0]) || !nativeQuestionToken(root[1]) {
			return resourceGenerationProjection{}, kaname.ErrSourceUnconfirmed
		}
		switch root[0] {
		case "iam.account", "iam.project", "iam.serviceAccount":
			continue
		}
		module, resource, ok := strings.Cut(root[0], ".")
		if !ok || module == "" || module == "iam" || resource == "" || strings.Contains(resource, ".") {
			return resourceGenerationProjection{}, kaname.ErrSourceUnconfirmed
		}
		// Полное точечное имя понадобится для чтения снятого ресурса.
		// Принадлежность каталогу проверяет тот же снимок при сборе графа.
		out.externalRoots = append(out.externalRoots, domain.ResourceRef{Type: root[0], ID: root[1]})
	}
	for _, output := range outputs {
		if len(output) != 2 || !nativeQuestionToken(output[0]) || !nativeQuestionToken(output[1]) || strings.Contains(output[0], ".") {
			return resourceGenerationProjection{}, kaname.ErrSourceUnconfirmed
		}
		out.outputRefs = append(out.outputRefs, output[0]+":"+output[1])
	}
	return out, ctx.Err()
}
