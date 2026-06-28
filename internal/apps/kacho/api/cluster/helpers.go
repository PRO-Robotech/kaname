// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster

// helpers.go — shared constants and helpers for cluster use-cases.

import "regexp"

// subjectIDRe — format validation for user-type subject IDs.
// Matches kacho-iam User ID format: `usr` (3-char prefix, NO underscore) +
// 17-char Crockford base32 body = 20 chars total.
var subjectIDRe = regexp.MustCompile(`^usr[0-9a-hjkmnp-tv-z]{17}$`)
