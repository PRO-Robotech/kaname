// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "time"

const (
	bindingConvergeIntervalKnob = "KANAME_BINDING_CONVERGE_INTERVAL_MS"
	bindingConvergeTimeoutKnob  = "KANAME_BINDING_CONVERGE_TIMEOUT_MS"
)

const (
	defaultBindingConvergeInterval = 5 * time.Minute
	defaultBindingConvergeTimeout  = 5 * time.Minute
)

type bindingConvergeWindows struct {
	Interval       time.Duration
	BindingTimeout time.Duration
}

// readBindingConvergeWindows — заготовка красной пробы.
func readBindingConvergeWindows() bindingConvergeWindows { return bindingConvergeWindows{} }
