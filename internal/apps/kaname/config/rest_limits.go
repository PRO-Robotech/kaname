// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// Умолчания потолков публичного REST-фронта.
const (
	DefaultRESTMaxBodyBytes int64 = 1 << 20
	DefaultRESTMaxInFlight  int   = 256
)

// RESTLimitsConfig — потолки публичного REST-фронта в объявлении посадки.
type RESTLimitsConfig struct {
	MaxBodyBytes *int64 `mapstructure:"max-body-bytes"`
	MaxInFlight  *int   `mapstructure:"max-in-flight"`
}

// RESTLimits — действующие потолки.
type RESTLimits struct {
	MaxBodyBytes int64
	MaxInFlight  int
}

// Effective — действующие потолки.
func (r RESTLimitsConfig) Effective() RESTLimits { return RESTLimits{} }

// Validate — страж потолков.
func (r RESTLimitsConfig) Validate(production bool) error {
	_ = production
	return nil
}
