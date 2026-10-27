// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

import (
	"context"

	"github.com/PRO-Robotech/corelib/operations"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// IsAnonymousSelfCheck admits only the credential-free, subject-free Check
// shape (kaname#959). Both public unary admission and the handler use this
// predicate. It grants no resource permission: the normal decision service
// evaluates the server-selected anonymous subject.
func IsAnonymousSelfCheck(ctx context.Context, req *iamv1.AuthorizeCheckRequest, modules moduleidentity.Roster) bool {
	if req == nil || req.GetSubject() != "" || req.GetContext() != nil ||
		req.GetRequiredRelation() != "" || req.GetResource() == nil || req.GetAction() == "" {
		return false
	}
	// Presence, not a default principal or a recognized credential scheme:
	// even an empty/unsupported Authorization must not become anonymous.
	if _, present := operations.PrincipalFromContextOK(ctx); present {
		return false
	}
	if _, present := callerorigin.From(ctx); present {
		return false
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if _, present := md[presentedcred.MetadataKey]; present {
			return false
		}
	}
	// A verified module is a different caller. A non-module certificate used
	// by our own REST front names the transport hop, not an end-user identity.
	// Модуль — объявленная пара перечня (kaname#984): тот же разбор, что у
	// политик вызывающего обоих слушателей.
	if _, module := modules.FromContext(ctx); module {
		return false
	}
	return true
}
