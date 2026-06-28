// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// Cluster — singleton (id = `cluster_kacho_root`). Корень
// иерархии cluster → account → project → resource.
// Используется как OpenFGA-объект для `cluster:cluster_kacho_root#system_admin@user:usr_xxx`.
type Cluster struct {
	ID          ClusterID
	Name        ClusterName
	Description Description
	CreatedAt   time.Time
}

func (c Cluster) Validate() error {
	var errs error
	errs = multierr.Append(errs, c.ID.Validate())
	errs = multierr.Append(errs, c.Name.Validate())
	errs = multierr.Append(errs, c.Description.Validate())
	return errs
}

// ClusterID — fixed literal `cluster_kacho_root` (singleton constraint в DB).
type ClusterID string

func (id ClusterID) Validate() error {
	if string(id) != ClusterSingletonID {
		return fmt.Errorf("Illegal argument cluster id %q (expected %q)", string(id), ClusterSingletonID)
	}
	return nil
}

// ClusterName — kebab-case (1..64).
type ClusterName string

func (n ClusterName) Validate() error {
	l := len(n)
	if l < 1 || l > 64 {
		return fmt.Errorf("Illegal argument cluster name: length must be 1..64")
	}
	return nil
}
