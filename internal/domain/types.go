// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"errors"
	"fmt"
	"regexp"
)

// Self-validating domain newtypes.
//
// `Validate()` enforces regex + length rules per field. Field semantics
// (e.g. Permission-regex with wildcard semantics) are encoded directly in
// the regexes below — change them by editing the regex and DB CHECKs in
// lockstep.

type (
	// AccountID / ProjectID / ... — newtypes over string, never bare ids.
	AccountID        string
	ProjectID        string
	UserID           string
	ServiceAccountID string
	GroupID          string
	RoleID           string
	AccessBindingID  string
	OperationID      string

	// SubjectID — opaque id (user, service_account, or group). The paired
	// SubjectType defines the semantics.
	SubjectID string

	// Names — every newtype has its own regex.
	AccountName    string
	ProjectName    string
	GroupName      string
	RoleName       string
	SvcAccountName string

	// OAuthClientName — человекочитаемое имя токена (SA-key / user-token).
	// Опционально: пустое допустимо (токен может нести только description).
	// Непустое обязано следовать той же kebab-конвенции, что и остальные
	// iam-имена (`^[a-z][-a-z0-9]{2,62}$`).
	OAuthClientName string

	DisplayName     string
	Email           string
	ExternalSubject string // OIDC sub
	Description     string

	LabelKey string
	LabelVal string
	// Labels — key→val map.
	Labels map[LabelKey]LabelVal

	Permission  string
	Permissions []Permission

	// SubjectType — enum: user|service_account|group.
	SubjectType string
	// ResourceType — enum (whitelist). Validated through `validResourceTypes`.
	ResourceType string
)

// SubjectType values.
const (
	SubjectTypeUser           SubjectType = "user"
	SubjectTypeServiceAccount SubjectType = "service_account"
	SubjectTypeGroup          SubjectType = "group"
)

// validResourceTypes — fixed enum. Extended via migrations.
//
// `cluster` is a singleton scope (resource_id MUST equal
// `domain.ClusterSingletonID` = "cluster_kacho_root"); see
// AccessBinding.Validate which enforces the singleton invariant. Unified into
// AccessBinding (Item #5) — replaces the standalone cluster_admin_grants
// path for new grants while migration 0004 backfills history.
var validResourceTypes = map[ResourceType]struct{}{
	"cluster":                   {},
	"account":                   {},
	"project":                   {},
	"vpc_network":               {},
	"vpc_subnet":                {},
	"vpc_address":               {},
	"vpc_route_table":           {},
	"vpc_security_group":        {},
	"vpc_gateway":               {},
	"vpc_network_interface":     {},
	"compute_instance":          {},
	"compute_disk":              {},
	"compute_image":             {},
	"compute_snapshot":          {},
	"loadbalancer_nlb":          {},
	"loadbalancer_target_group": {},
	"iam_account":               {},
	"iam_project":               {},
	"iam_user":                  {},
	"iam_service_account":       {},
	"iam_group":                 {},
	"iam_role":                  {},
	"*":                         {},
}

// Regex / limits — centralised so domain.Validate and the DB CHECKs
// (migration `0001_initial.sql`) agree.
var (
	nameKebabRe         = regexp.MustCompile(`^[a-z][-a-z0-9]{2,62}$`)
	roleNameCustomRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)
	roleNameSystemRe    = regexp.MustCompile(`^roles/[a-z]+\.[a-z]+$`)
	emailRe             = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	labelKeyRe          = regexp.MustCompile(`^[a-z][-_./@a-z0-9]{0,62}$`)
	permissionElementRe = regexp.MustCompile(`^(\*|[a-z][a-z0-9-]*)\.(\*|[a-z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z0-9_-]+)\.(\*|[a-z][a-zA-Z0-9_-]*)$`)
)

// Validate — per newtype.

func (n AccountName) Validate() error    { return validateKebabName("name", string(n)) }
func (n ProjectName) Validate() error    { return validateKebabName("name", string(n)) }
func (n GroupName) Validate() error      { return validateKebabName("name", string(n)) }
func (n SvcAccountName) Validate() error { return validateKebabName("name", string(n)) }

// Validate — OAuthClientName: пустое имя допустимо (токен может нести только
// description); непустое обязано соответствовать kebab-конвенции.
func (n OAuthClientName) Validate() error {
	if n == "" {
		return nil
	}
	return validateKebabName("name", string(n))
}

// RoleName — two forms: custom (without `roles/` prefix) or system
// (`roles/<module>.<role>`). Both are accepted here; the use-case layer
// constrains context (Create custom role accepts only the custom form;
// system roles come from seed migrations only).
func (n RoleName) Validate() error {
	if roleNameCustomRe.MatchString(string(n)) || roleNameSystemRe.MatchString(string(n)) {
		return nil
	}
	return fmt.Errorf("Illegal argument name: must match ^[a-z][a-z0-9_]{0,40}$ (custom) or ^roles/[a-z]+\\.[a-z]+$ (system)")
}

func (d DisplayName) Validate() error {
	if len(d) == 0 || len(d) > 128 {
		return fmt.Errorf("Illegal argument display_name: length must be 1..128")
	}
	return nil
}

func (e Email) Validate() error {
	if len(e) == 0 || len(e) > 254 || !emailRe.MatchString(string(e)) {
		return fmt.Errorf("Illegal argument email: invalid format")
	}
	return nil
}

func (s ExternalSubject) Validate() error {
	if len(s) == 0 || len(s) > 256 {
		return fmt.Errorf("Illegal argument external_id: length must be 1..256")
	}
	return nil
}

func (d Description) Validate() error {
	if len(d) > 256 {
		return fmt.Errorf("Illegal argument description: length must be <=256")
	}
	return nil
}

func (k LabelKey) Validate() error {
	if !labelKeyRe.MatchString(string(k)) {
		return fmt.Errorf("Illegal argument label key: invalid format")
	}
	return nil
}

func (v LabelVal) Validate() error {
	if len(v) > 63 {
		return fmt.Errorf("Illegal argument label value: length must be <=63")
	}
	return nil
}

// Validate — Labels: cardinality ≤64; each pair via LabelKey/LabelVal.
func (l Labels) Validate() error {
	if len(l) > 64 {
		return fmt.Errorf("Illegal argument labels: cardinality must be <=64")
	}
	for k, v := range l {
		if err := k.Validate(); err != nil {
			return err
		}
		if err := v.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate — Permission: one element with wildcard semantics.
func (p Permission) Validate() error {
	if !permissionElementRe.MatchString(string(p)) {
		return fmt.Errorf("Illegal argument permissions: invalid format")
	}
	return nil
}

// Validate — Permissions: cardinality 1..1024; each — Permission.Validate.
//
// The ≥1 lower bound applies to the LEGACY permissions-only role path (a role
// authored as a bare permission set must carry at least one). Cap raised 256→1024
// in lockstep with the DB CHECK iam_permissions_valid (migration 0025) and the
// proto (size) bound, so the compiled-permission set derived from a role's rules
// (CompileRules, ≤MaxCompiledPermissions) always passes domain + DB validation
// (acceptance R-12 / A-12). A rules-role uses ValidateCompiled (no lower bound) —
// a label-only role compiles to an EMPTY set by design (ARM_LABELS excluded).
func (p Permissions) Validate() error {
	if len(p) == 0 {
		return fmt.Errorf("Illegal argument permissions: must contain at least 1")
	}
	return p.validateGrammarAndCap()
}

// ValidateCompiled validates the INTERNAL compiled-permission projection of a
// rules-role: the 4-segment grammar parity + the ≤1024 cap, but WITHOUT the ≥1
// lower bound. A rules-role whose rules are ALL ARM_LABELS compiles to an EMPTY
// permission set (matchLabels is not compiled — R-7 / fix #8), which is valid; the
// authority lives in rules[], not permissions[]. Only the legacy permissions-only
// path keeps the ≥1 floor (Validate). Acceptance A-10 (label-only positive).
func (p Permissions) ValidateCompiled() error {
	return p.validateGrammarAndCap()
}

// validateGrammarAndCap — shared 4-seg grammar + ≤1024 cap check (no lower bound).
func (p Permissions) validateGrammarAndCap() error {
	if len(p) > MaxCompiledPermissions {
		return fmt.Errorf("Illegal argument permissions: cardinality must be <=%d", MaxCompiledPermissions)
	}
	for _, perm := range p {
		if err := perm.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate — SubjectType — enum check.
func (s SubjectType) Validate() error {
	switch s {
	case SubjectTypeUser, SubjectTypeServiceAccount, SubjectTypeGroup:
		return nil
	default:
		return fmt.Errorf("Illegal argument subject_type %q (allowed: user|service_account|group)", string(s))
	}
}

// Validate — ResourceType — whitelist check.
func (r ResourceType) Validate() error {
	if _, ok := validResourceTypes[r]; ok {
		return nil
	}
	return fmt.Errorf("Illegal argument resource_type %q", string(r))
}

// validateKebabName — shared helper for AccountName/ProjectName/GroupName/SvcAccountName.
func validateKebabName(field, v string) error {
	if !nameKebabRe.MatchString(v) {
		return fmt.Errorf("Illegal argument %s: must match ^[a-z][-a-z0-9]{2,62}$", field)
	}
	return nil
}

// ErrEmpty — sentinel for empty required fields (used in NULL-validation
// before repo).
var ErrEmpty = errors.New("required field is empty")
