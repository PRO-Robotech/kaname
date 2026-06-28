// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// builders.go — constructors / factories for domain objects.
//
// Most builders are trivial because default roles are seeded by the
// migration (`0001_initial.sql`) and have no runtime logic beyond
// id/name/permissions. This file holds the non-trivial factories — add
// new ones here as the need appears (e.g. NewAccount/NewProject builders
// that pre-validate, DefaultSystemRoles helper for unit tests, etc.).
