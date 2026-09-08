// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// Cluster — singleton (id = `cluster_root`). Корень
// иерархии cluster → account → project → resource.
// Используется как объект модели прав для `cluster:cluster_root#system_admin@user:usr_xxx`.
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

// ClusterID — fixed literal `cluster_root` (singleton constraint в DB).
type ClusterID string

func (id ClusterID) Validate() error {
	if string(id) != ClusterSingletonID {
		return fmt.Errorf("Illegal argument cluster id %q (expected %q)", string(id), ClusterSingletonID)
	}
	return nil
}

// ClusterName — отображаемое имя singleton-кластера: длина 1..64 и БОЛЬШЕ
// ничего. Здесь стояло «kebab-case», и это было обещанием алфавита, которого
// проверка не делает ни в одной ветке.
//
// Форму имени ресурса (`pkg/validate/nameform`) поле НЕ несёт намеренно: оно
// не задаётся клиентом — значение пишет посевная миграция, а у службы кластера
// нет глагола, который бы его менял.
type ClusterName string

func (n ClusterName) Validate() error {
	l := len(n)
	if l < 1 || l > 64 {
		return fmt.Errorf("Illegal argument cluster name: length must be 1..64")
	}
	return nil
}
