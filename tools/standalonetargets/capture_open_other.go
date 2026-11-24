//go:build !linux

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets

import (
	"errors"
	"os"
)

// Без проверенного no-follow open capture остаётся недоверенным; пакет собирается.
func standaloneOpenNoFollow(_ *os.Root, _ string, _ bool) (*os.File, error) {
	return nil, errors.New("строгое открытие capture на этой платформе не поддержано")
}

func standaloneOpenAt(_ *os.File, _ string, _ bool) (*os.File, error) {
	return nil, errors.New("строгое открытие capture на этой платформе не поддержано")
}
