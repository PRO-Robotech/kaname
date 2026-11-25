// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"fmt"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/listfilter"
)

// parseListFilter переводит ошибки фильтра в INVALID_ARGUMENT.
func parseListFilter(expr string, allowed ...string) (*listfilter.Expression, error) {
	ast, err := listfilter.Parse(expr, allowed)
	if err != nil {
		return nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	return ast, nil
}

func listFilterSQL(expr *listfilter.Expression, argIdx int) (string, []any) {
	if expr.Label != nil {
		return labelFilterSQL(*expr.Label, argIdx)
	}
	return expr.ToSQL(argIdx)
}

func labelFilterSQL(label listfilter.Label, argIdx int) (string, []any) {
	return fmt.Sprintf("labels @> jsonb_build_object($%d::text, $%d::text)", argIdx, argIdx+1),
		[]any{string(label.Key), label.Value}
}
