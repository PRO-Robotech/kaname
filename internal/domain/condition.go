// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"go.uber.org/multierr"
)

// Condition — folder-scoped reusable CEL-like expression (served by
// `ConditionsService`). Distinct from the legacy per-binding condition overlay
// (the `cond_…` AccessBindingConditionID link on AccessBinding):
//
//   - the legacy overlay was bound 1:1 to one AccessBinding via the
//     `binding_id` FK and carried a whitelisted `expression` (mfa_fresh, …).
//   - `Condition` is a standalone, folder-scoped resource that stores a
//     free-form CEL expression + JSON-Schema for its parameters. Referenced
//     by `AccessBinding.condition_ref.condition_id` (oneof) and evaluated by
//     OpenFGA Conditions on every Check.
//
// Resource id prefix: `cnd`.
type Condition struct {
	ID               ConditionID
	FolderID         string
	CreatedAt        time.Time
	Name             string
	Description      string
	Labels           map[string]string
	Expression       string
	ParametersSchema ConditionParametersSchema
	Status           ConditionStatus
	ResourceVersion  int64
}

// Validate — sync-fast field-level validation; full CEL compilation is done
// by ConditionsEvaluator at request time (allows fmt-style errors for
// per-binding pre-check) and asynchronously by OpenFGA on
// `WriteAuthorizationModel`.
func (c Condition) Validate() error {
	var errs error
	errs = multierr.Append(errs, c.ID.Validate())
	if c.FolderID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument folder_id: required"))
	} else if len(c.FolderID) > 20 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument folder_id: length must be <=20"))
	}
	if c.Name == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument name: required"))
	} else if !conditionNameRe.MatchString(c.Name) {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument name: must match ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$"))
	}
	if len(c.Description) > 256 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument description: length must be <=256"))
	}
	if c.Expression == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument expression: required"))
	} else if len(c.Expression) > 2048 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument expression: length must be <=2048"))
	}
	errs = multierr.Append(errs, c.Status.Validate())
	return errs
}

// ConditionID — `cnd_<...>` (migration 0017 CHECK).
type ConditionID string

var (
	conditionIDRe   = regexp.MustCompile(`^cnd[a-z0-9]{1,17}$`)
	conditionNameRe = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

func (id ConditionID) Validate() error {
	if id == "" {
		return nil
	}
	if !conditionIDRe.MatchString(string(id)) {
		return fmt.Errorf("Illegal argument condition_id: must match ^cnd[a-z0-9]{1,17}$")
	}
	return nil
}

func (id ConditionID) String() string { return string(id) }

// ConditionStatus — lifecycle enum (mirror of iamv1.Condition_Status).
type ConditionStatus string

const (
	ConditionStatusUnspecified ConditionStatus = ""
	ConditionStatusCreating    ConditionStatus = "CREATING"
	ConditionStatusActive      ConditionStatus = "ACTIVE"
	ConditionStatusDeleting    ConditionStatus = "DELETING"
	ConditionStatusError       ConditionStatus = "ERROR"
)

func (s ConditionStatus) Validate() error {
	switch s {
	case ConditionStatusUnspecified, ConditionStatusCreating, ConditionStatusActive,
		ConditionStatusDeleting, ConditionStatusError:
		return nil
	default:
		return fmt.Errorf("Illegal argument status %q (not in whitelist)", string(s))
	}
}

// ConditionParametersSchema — JSON Schema describing the shape of `params`
// that callers pass at AccessBinding.condition_ref time. Stored as
// json.RawMessage so we don't recursively validate JSON Schema here — the
// handler validates the schema-meta on Create.
type ConditionParametersSchema json.RawMessage

func (p ConditionParametersSchema) MarshalJSON() ([]byte, error) {
	if len(p) == 0 {
		return []byte("{}"), nil
	}
	return []byte(p), nil
}

func (p *ConditionParametersSchema) UnmarshalJSON(data []byte) error {
	*p = ConditionParametersSchema(append([]byte(nil), data...))
	return nil
}

// PrefixConditionResource — id-prefix for kacho-corelib/ids.NewID for the
// standalone Condition resource (`cnd_…`). Distinct from the legacy
// `cond_…` AccessBindingConditionID overlay link.
const PrefixConditionResource = "cnd"
