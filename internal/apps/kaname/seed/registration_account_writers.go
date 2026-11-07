// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package seed

import (
	"context"
	"fmt"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"sort"
	"strings"
)

// RegistrationWriterPlan — конечный, проверенный вход установки. Отключённые
// записи — исключения только первого переключения; полномочий они никогда не создают.
type RegistrationWriterPlan struct {
	// Оператор подтверждает, что вход обслуживает только ревизия с проверкой аккаунта.
	RetireClusterWriter bool
	Assignments         []domain.RegistrationAccountWriter
	Disabled            []domain.DisabledRegistrationModule
}

type RegistrationWriterStore interface {
	ApplyRegistrationAccountWriters(context.Context, RegistrationWriterPlan) error
}

// ApplyRegistrationAccountWriters проверяет весь план по ТОМУ ЖЕ
// перечню модулей, что AuthN, до его атомарного применения в постоянном хранилище.
func ApplyRegistrationAccountWriters(ctx context.Context, store RegistrationWriterStore, roster moduleidentity.Roster, plan RegistrationWriterPlan) error {
	modules := map[string]bool{}
	for _, m := range roster.Identities() {
		modules[m.Service] = true
	}
	ids, pairs := map[string]bool{}, map[string]bool{}
	var problems []string
	for _, a := range plan.Assignments {
		if strings.TrimSpace(a.AssignmentID) == "" || strings.ContainsAny(a.AssignmentID, "* \t\n") || a.AccountID == "" || a.AccountID == "*" || !modules[a.Module] {
			problems = append(problems, fmt.Sprintf("invalid assignment %q (%s/%s)", a.AssignmentID, a.AccountID, a.Module))
		}
		if ids[a.AssignmentID] || pairs[a.AccountID+"/"+a.Module] {
			problems = append(problems, "duplicate assignment "+a.AssignmentID)
		}
		ids[a.AssignmentID], pairs[a.AccountID+"/"+a.Module] = true, true
	}
	disabled := map[string]bool{}
	for _, d := range plan.Disabled {
		key := d.AccountID + "/" + d.Module
		if d.AccountID == "" || d.AccountID == "*" || !modules[d.Module] || strings.TrimSpace(d.Reason) == "" || disabled[key] || pairs[key] {
			problems = append(problems, "invalid disabled-module exception "+key)
		}
		disabled[key] = true
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("registration-account-writers preflight: %s", strings.Join(problems, "; "))
	}
	if store == nil {
		return fmt.Errorf("registration-account-writers store is required")
	}
	return store.ApplyRegistrationAccountWriters(ctx, plan)
}
