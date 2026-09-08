// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"github.com/PRO-Robotech/kacho/pkg/filter"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// parseListFilter parses a List `filter` expression against the closed whitelist
// the calling reader declares, and is the ONLY filter parser in this package.
//
// It replaces two hand-rolled parsers that reported "not my shape" with a bare
// bool. Every caller of those spelled `if v, ok := parse…(f.Filter); ok { … }`
// with no else, so an expression the service could not honour added no WHERE
// condition at all and List answered with the FULL page: the caller asked to
// narrow, got everything back, and had no way to tell that from a genuine result
// (#445). api-conventions.md §"Принято-и-проигнорировано — ЗАПРЕЩЕНО" allows three
// outcomes — implement, refuse explicitly, drop from the contract — and silently
// accepting is not among them. Refusing names the offending field, so a caller who
// misspells `name` learns which token was wrong instead of reading a full table as
// a search result.
//
// Delegating to pkg/filter also puts iam on the same grammar and the same error
// texts as the other owners (vpc, compute, storage, nlb, registry), rather than a
// private near-copy that had already drifted: the local parsers accepted an
// unterminated value like `name="unclosed` because they only checked the first and
// last byte.
//
// Returns (nil, nil) for an empty expression, meaning "no filter" — the caller adds
// no condition. Any parse failure is ErrInvalidArg, which the handler layer maps to
// INVALID_ARGUMENT, the same path page_token validation already uses.
func parseListFilter(expr string, allowed ...string) (*filter.FilterAST, error) {
	ast, err := filter.Parse(expr, allowed)
	if err != nil {
		return nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	return ast, nil
}
