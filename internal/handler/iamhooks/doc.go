// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iamhooks — HTTP webhook handlers for the kaname AuthN core:
// хуки поставщика токенов (выдача, продление) и хуки поставщика личности
// (заведение по первому входу, завершение восстановления доступа).
//
// Все эти handlers слушают только на cluster-internal HTTP listener
// (config authn.hooks-http-endpoint, default tcp://0.0.0.0:9092). Не публикуются
// на external TLS endpoint (ban #6 — Internal.* не на external endpoint).
//
// Handlers:
//
//   - TokenHookHandler     POST /iam/v1/hooks/token     (Hydra access_token webhook)
//   - RefreshHookHandler   POST /iam/v1/hooks/refresh   (Hydra refresh_token webhook)
//   - ProvisionHookHandler POST /iam/v1/hooks/provision (Kratos registration/login → UpsertFromIdentity)
//   - RecoveryHookHandler  POST /iam/v1/hooks/recovery  (Kratos recovery-completed → OnRecoveryCompleted)
//
// ПЕРЕЧЕНЬ ВЫШЕ — ОПИСЬ ПОЛОСЫ, И ОНА СВЕРЯЕТСЯ С ПРОИЗВОДИТЕЛЕМ. Четвёртый
// маршрут приехал позже трёх соседних, а эта шапка осталась прежней: опись
// называла три маршрута из четырёх, и читатель шапки имел все основания решить,
// что четвёртого нет. Теперь полноту держит проба
// `route_prose_names_every_route_test.go`: всякая шапка, назвавшая БОЛЕЕ ОДНОГО
// маршрута, обязана назвать каждый маршрут [Routes].
//
// Authentication: Bearer X-Kacho-Hook-Token validated против
// authn.hook-shared-secret (либо ENV KANAME_HOOK_TOKEN).
package iamhooks
