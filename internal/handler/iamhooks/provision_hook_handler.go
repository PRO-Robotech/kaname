// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// provision_hook_handler.go — Kratos user-provisioning webhook (audit C4).
//
// POST /iam/v1/hooks/provision
//
// Kratos (configured selfservice.flows.{registration,login}.after.*.web_hook)
// вызывает этот endpoint после успешной регистрации / логина. Payload —
// рендер `identity-payload.jsonnet` (kacho-deploy), который маппит Kratos
// identity → {external_id, email, display_name}. Handler делегирует
// UpsertFromIdentity use-case'у (тот же, что обслуживает gRPC
// InternalUserService.UpsertFromIdentity на :9091) — bootstrap нового Account/
// Project/AccessBinding для нового identity, либо активация PENDING-invite.
//
// До C4 эти web_hook'и POST'или на gRPC :9091 c REST-style путем
// `/iam/v1/internal/users:upsertFromIdentity` — путь, которого на чистом gRPC
// (HTTP/2) listener не существует → каждый hook молча падал → пользователь
// регистрировался, но никогда не зеркалился в kacho_iam (нет project/
// namespace). C4 переводит provisioning на :9092 HTTP hooks listener
// (Hydra-hook'и уже там) и вызывает use-case in-process.
package iamhooks

import (
	"context"
	"log/slog"
	"net/http"
)

// ProvisionHookConfig — runtime config для provision hook.
type ProvisionHookConfig struct {
	HookSharedSecret string
}

// ProvisionInput — decoded identity-payload (см. identity-payload.jsonnet в
// kacho-deploy). Handler-local DTO: iamhooks НЕ импортирует use-case-пакет;
// composition root маппит это в user.UpsertFromIdentityInput.
type ProvisionInput struct {
	ExternalID  string
	Email       string
	DisplayName string
}

// UserProvisioner — narrow port. Реализуется adapter'ом из
// cmd/kacho-iam, который вызывает UpsertFromIdentityUseCase.Execute. Handler
// не зависит от transport / use-case / operations-типов.
type UserProvisioner interface {
	Provision(ctx context.Context, in ProvisionInput) error
}

// ProvisionHookHandler — HTTP handler.
type ProvisionHookHandler struct {
	cfg         ProvisionHookConfig
	provisioner UserProvisioner
	logger      *slog.Logger
}

// NewProvisionHookHandler — constructor.
func NewProvisionHookHandler(
	cfg ProvisionHookConfig,
	provisioner UserProvisioner,
	logger *slog.Logger,
) *ProvisionHookHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &ProvisionHookHandler{
		cfg:         cfg,
		provisioner: provisioner,
		logger:      logger,
	}
}

// kratosProvisionRequest — payload от Kratos web_hook (рендер
// identity-payload.jsonnet). Поля совпадают с тем, что эмитит jsonnet:
//
//	external_id  — Kratos identity id (ctx.identity.id → OIDC sub),
//	email        — primary email trait,
//	display_name — optional human-readable name trait.
type kratosProvisionRequest struct {
	ExternalID  string `json:"external_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// ServeHTTP реализует http.Handler.
func (h *ProvisionHookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if !requireHookAuth(w, r, h.cfg.HookSharedSecret) {
		return
	}

	var payload kratosProvisionRequest
	if !decodeHookBody(w, r, &payload, h.logger, "provision_hook") {
		return
	}
	defer func() { _ = r.Body.Close() }()

	if payload.ExternalID == "" {
		h.logger.Warn("provision_hook: missing external_id in payload")
		http.Error(w, `{"error":"missing_external_id"}`, http.StatusBadRequest)
		return
	}

	// kratosProvisionRequest and ProvisionInput share the same field set; a
	// direct conversion avoids a field-by-field copy (staticcheck S1016).
	in := ProvisionInput(payload)
	if err := h.provisioner.Provision(r.Context(), in); err != nil {
		// LOG так, чтобы сломанный hook был НАБЛЮДАЕМ (а не молчал — вся суть
		// C4). 5xx → Kratos не считает hook успешным.
		// PII: the end-user email is intentionally NOT logged — external_id is the
		// stable non-PII correlation key; emails must not leak into log sinks.
		h.logger.Error("provision_hook: user provisioning failed",
			"external_id", payload.ExternalID, "err", err)
		http.Error(w, `{"error":"provision_failed"}`, http.StatusInternalServerError)
		return
	}

	h.logger.Info("provision_hook: user provisioned from identity",
		"external_id", payload.ExternalID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Kratos трактует 200 (без тела либо с JSON-объектом) как hook-OK. Пустой
	// JSON-объект — безопасный no-op (мы не модифицируем identity).
	_, _ = w.Write([]byte("{}"))
}
