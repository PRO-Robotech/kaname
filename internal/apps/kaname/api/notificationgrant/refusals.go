// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package notificationgrant

// refusals.go — таблица отказов Р5 приёмки NTF-1: тексты, коды и `reason`
// — часть контракта и меняются только тикетом. Отказы синхронны, Operation при
// отказе не создаётся.

import (
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/validate/nameform"

	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

const (
	// resourceType — тип ресурса в метаданных отказа.
	resourceType = "notification_namespace"

	reasonInvalidResourceID = "INVALID_RESOURCE_ID"
	reasonResourceNotFound  = "RESOURCE_NOT_FOUND"
	// reasonGrantState — переход не применим к состоянию записи выдачи.
	reasonGrantState = "NOTIFICATION_GRANT_STATE"

	// unavailableText — сбой чтения хранилища kaname: фиксированный текст без
	// текста драйвера (NTF1-F23).
	unavailableText = "notification grant service temporarily unavailable"
)

// refusal — статус с ErrorInfo домена отказов kaname.
func refusal(code codes.Code, reason, namespace, message string) error {
	st := status.New(code, message)
	// Метаданные называют пространство всегда, в том числе пустое: «поле
	// пусто» и «поля нет» клиент различает.
	meta := map[string]string{"resource_id": namespace}
	meta["resource_type"] = resourceType
	enriched, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason:   reason,
		Domain:   refusaldomain.For(refusaldomain.ServiceIAM),
		Metadata: meta,
	})
	if err != nil {
		return st.Err()
	}
	return enriched.Err()
}

// fieldRefusal — INVALID_ARGUMENT с нарушением поля, без reason.
func fieldRefusal(field, message string) error {
	st := status.New(codes.InvalidArgument, message)
	enriched, err := st.WithDetails(&errdetails.BadRequest{
		FieldViolations: []*errdetails.BadRequest_FieldViolation{{Field: field, Description: message}},
	})
	if err != nil {
		return st.Err()
	}
	return enriched.Err()
}

// validateNamespace — форма пространства: непусто, DNS label.
func validateNamespace(namespace string) error {
	if namespace == "" {
		return refusal(codes.InvalidArgument, reasonInvalidResourceID, namespace, "namespace: required")
	}
	if !nameform.OK(namespace) {
		return refusal(codes.InvalidArgument, reasonInvalidResourceID, namespace,
			fmt.Sprintf("invalid notification_namespace id '%s'", namespace))
	}
	return nil
}

// validateTemplate — форма шаблона: DNS label.
func validateTemplate(template string) error {
	if !nameform.OK(template) {
		return fieldRefusal("template", fmt.Sprintf("template: invalid name '%s'", template))
	}
	return nil
}

// grantNotFound — записи выдачи нет.
func grantNotFound(namespace string) error {
	return refusal(codes.NotFound, reasonResourceNotFound, namespace,
		fmt.Sprintf("NotificationNamespace %s not found", namespace))
}

// grantState — переход не применим: `Revoke` отозванного («is already
// revoked») либо `Restore` без надгробия («is not revoked»).
func grantState(namespace string, template *string, predicate string) error {
	subject := "NotificationNamespace " + namespace
	if template != nil {
		subject += " template " + *template
	}
	return refusal(codes.FailedPrecondition, reasonGrantState, namespace, subject+" "+predicate)
}
