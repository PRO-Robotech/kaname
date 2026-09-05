// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package repomock — mock-impl iface'ов из `internal/repo/kacho/*` для unit-тестов
// use-case'ов (parity с kacho-vpc/internal/repo/repomock).
//
// Моки генерируются через `mockery` либо рукописными struct'ами с in-memory
// map (parity с kacho-vpc).
//
// Использование (из service-unit-теста):
//
//	repo := repomock.NewRepository()
//	uc := accountapp.NewCreateAccountUseCase(repo, opsRepoMock)
//	op, err := uc.Run(ctx, ...)
//	repomock.AwaitOpDone(t, opsRepoMock, op.ID)
package repomock
