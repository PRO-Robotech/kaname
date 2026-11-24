// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package installruntime

import (
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"gopkg.in/yaml.v3"
)

// RegistrationWriterPlan — конечный вход фикстуры, отдельный от ExtraConfig.
// nil намеренно опускает объявление; пустой assignments явно выключает регистраторов.
// На этих стендах только новая ревизия, поэтому прежнюю кластерную выдачу можно снять.
type RegistrationWriterPlan struct {
	RetireClusterWriter bool                                `yaml:"retire-cluster-writer" json:"retireClusterWriter"`
	Assignments         []domain.RegistrationAccountWriter  `yaml:"assignments" json:"assignments"`
	Disabled            []domain.DisabledRegistrationModule `yaml:"disabled" json:"disabled"`
}

func EmptyRegistrationWriterPlan() *RegistrationWriterPlan {
	return &RegistrationWriterPlan{RetireClusterWriter: true, Assignments: []domain.RegistrationAccountWriter{}, Disabled: []domain.DisabledRegistrationModule{}}
}

// RegistryRegistrationWriterPlan называет только известные аккаунты вызывающего.
// ID сохраняются при смене порядка, повторе, параллельном запуске и восстановлении.
func RegistryRegistrationWriterPlan(accounts []string) *RegistrationWriterPlan {
	plan := EmptyRegistrationWriterPlan()
	for _, account := range accounts {
		plan.Assignments = append(plan.Assignments, domain.RegistrationAccountWriter{
			AssignmentID: "rid-registry-" + domain.DerivedIDSuffix("rid-registration-writer:registry:"+account),
			AccountID:    account,
			Module:       "registry",
		})
	}
	return plan
}

func CloneRegistrationWriterPlan(plan *RegistrationWriterPlan) *RegistrationWriterPlan {
	if plan == nil {
		return nil
	}
	out := *plan
	if plan.Assignments != nil {
		out.Assignments = append([]domain.RegistrationAccountWriter{}, plan.Assignments...)
	}
	if plan.Disabled != nil {
		out.Disabled = append([]domain.DisabledRegistrationModule{}, plan.Disabled...)
	}
	return &out
}

// FullStartupConfig общий для Session и всех дочерних полных запусков.
// Точный типизированный план входит в настоящий YAML отдельно от ExtraConfig.
func FullStartupConfig(doc map[string]any, plan *RegistrationWriterPlan) ([]byte, error) {
	out := make(map[string]any, len(doc)+1)
	for key, value := range doc {
		if strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key)) == "registrationaccountwriters" {
			return nil, fmt.Errorf("reserved typed registration writer profile key %s", key)
		}
		out[key] = value
	}
	if plan != nil {
		writers := map[string]any{"retire-cluster-writer": plan.RetireClusterWriter, "assignments": plan.Assignments, "disabled": plan.Disabled}
		if plan.Assignments == nil {
			writers["assignments"] = nil
		}
		if plan.Disabled == nil {
			writers["disabled"] = nil
		}
		out["registration-account-writers"] = writers
	}
	return yaml.Marshal(out)
}
