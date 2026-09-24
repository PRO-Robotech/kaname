// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build race

package check

// surfaceListRace — сборка пробы под -race: данные экспорта радиуса берутся той
// же сборкой, что уже лежит в кэше прогона, а не собираются второй раз без неё.
const surfaceListRace = true
