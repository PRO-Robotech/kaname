// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

import (
	"context"
	"strconv"

	"github.com/PRO-Robotech/corelib/acrlevel"
	authzv1 "github.com/PRO-Robotech/corelib/api/corelib/authz/v1"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func catalogPublicationACR(fullMethod string) (string, bool) {
	var method protoreflect.Name
	switch fullMethod {
	case iamv1.CatalogPublicationService_PlanPublication_FullMethodName:
		method = "PlanPublication"
	case iamv1.CatalogPublicationService_ApplyPublication_FullMethodName:
		method = "ApplyPublication"
	default:
		return "", false
	}
	file := iamv1.File_kaname_cloud_iam_v1_catalog_publication_service_proto
	service := file.Services().ByName("CatalogPublicationService")
	if service == nil {
		return "", true
	}
	descriptor := service.Methods().ByName(method)
	if descriptor == nil {
		return "", true
	}
	acr, _ := proto.GetExtension(descriptor.Options(), authzv1.E_RequiredAcrMin).(string)
	return acr, true
}

// RequireCatalogPublicationACR требует собственное проверенное удостоверение
// человека и ступень из контракта Kaname. Полномочие system_admin независимо
// проверяет обработчик: машинное исключение из ACR публикации не предоставлено.
func RequireCatalogPublicationACR(ctx context.Context, fullMethod string) error {
	required, known := catalogPublicationACR(fullMethod)
	if !known || acrlevel.Rank(required) == 0 {
		return AuthzBackendUnavailable()
	}
	principal, named := operations.PrincipalFromContextOK(ctx)
	if !callerorigin.IsPresentedCredential(ctx) || !named || principal.ID == "" || principal.Type != "user" {
		return PermissionDenied()
	}
	acr, _ := callerorigin.AssuranceFrom(ctx)
	if grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
		PrincipalType: principal.Type,
		PresentedACR:  acr,
		RequiredACR:   required,
	}) != grpcsrv.StepUpAllow {
		return &stepUpRequired{challenge: iamerr.StepUpChallenge(
			strconv.Itoa(acrlevel.Rank(required)), strconv.Itoa(acrlevel.Rank(acr)))}
	}
	return nil
}
