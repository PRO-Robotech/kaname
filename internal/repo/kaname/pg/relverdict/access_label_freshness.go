// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"fmt"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Pending — отдельный исход источника, не имя условия модели и не отказ.
// Пустой успешный List скрыл бы неподтверждённое право от вызывающего.
var ErrAccessLabelProjectionPending = fmt.Errorf("%w: protected access label projection is pending", iamerr.ErrUnavailable)

const pendingFactArm = "__access_label_pending_v1"

// Проверка exact fact key идёт в том же statement/snapshot, что сам факт.
// NULL от нарушенного getter также не является доказательством свежести.
const factFreshSQL = "kaname.authority_access_label_fact_fresh_v1(f.object_type,f.object_id,f.relation,f.subject)"
const factFreshnessArmSQL = "CASE WHEN " + factFreshSQL + " IS TRUE THEN ''::text ELSE '" + pendingFactArm + "'::text END AS arm"
