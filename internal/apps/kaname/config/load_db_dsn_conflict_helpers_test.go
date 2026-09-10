// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import "os"

// writeFile — узкий помощник для фикстуры файла настроек.
func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
