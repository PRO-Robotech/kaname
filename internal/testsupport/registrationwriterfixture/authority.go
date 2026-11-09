// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
// Пакет registrationwriterfixture предоставляет явный двойник полномочий для
// проб несвязанного поведения регистрации. Он не доказывает начальную установку/mTLS.
package registrationwriterfixture

import "context"

type Authority struct {
	Module        string
	CatalogModule string
}

func (a Authority) Authorize(context.Context) (string, error)    { return a.Module, nil }
func (Authority) AuthorizeAccount(context.Context, string) error { return nil }

func (a Authority) AuthorizeCatalogModule(context.Context) (string, error) {
	if a.CatalogModule != "" {
		return a.CatalogModule, nil
	}
	return a.Module, nil
}
