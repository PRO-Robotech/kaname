// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import "errors"

// ErrObjectRefInManifest — манифест модуля называет КОНКРЕТНЫЙ объект.
var ErrObjectRefInManifest = errors.New("manifest: a module manifest names a concrete object")
