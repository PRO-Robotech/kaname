// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleseed

import "errors"

// ErrBindingTargetNotWholeScope — выдача посева действует не на ярус целиком.
var ErrBindingTargetNotWholeScope = errors.New("moduleseed: seed access binding target is not allInScope")
