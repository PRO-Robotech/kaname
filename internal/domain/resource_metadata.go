// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// ResourceMetadata — метки зарегистрированного объекта в представлении Kaname.
type ResourceMetadata struct {
	ResourceType string
	ResourceID   string
	Labels       map[string]string
	AccessLabels map[string]string
}
