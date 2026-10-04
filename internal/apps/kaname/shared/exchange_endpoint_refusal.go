// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ExchangeEndpointAbsent — отказ выдачи ключа, который обменивается
// токен-эндпоинтом платформы, на посадке, где эндпоинта нет (kaname#362 —
// ключ служебной учётки, kaname#547 — ключевая пара человека).
//
// Текст ОДИН на оба глагола выдачи: два написания одного отказа разошлись бы,
// и вызывающий читал бы по различию, каким путём спрашивал. Отказ называет
// ручку, которой снимается.
func ExchangeEndpointAbsent(kind domain.CredentialKind) error {
	return status.Errorf(codes.FailedPrecondition,
		"credential_kind %s: authn.client-token.enabled is false — this key is exchanged for a "+
			"token on the platform token endpoint, and this landing does not run one", kind)
}
