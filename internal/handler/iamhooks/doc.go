// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package iamhooks — HTTP webhook handlers for the kacho-iam AuthN core
// (Hydra OAuth2 token hooks).
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
//
// Authentication: Bearer X-Kacho-Hook-Token validated против
// authn.hook-shared-secret (либо ENV KACHO_IAM_HOOK_TOKEN).
package iamhooks
