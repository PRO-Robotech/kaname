// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_hook_handler.go — завершение восстановления пароля, приходящее от
// провайдера личности по HTTP на слушатель хуков (:9092).
//
// # Почему этот файл появился позже трёх соседних
//
// До него хук восстановления оставался нацеленным на ЛЕГАСИ gRPC-порт с
// REST-подобным путём — тем самым, которого на чистом gRPC не существует. Это
// ровно тот дефект, который уже чинили у заведения пользователя: провайдер
// POST'ит, получает отказ уровня транспорта, считает вызов сделанным, и до нас
// событие не доезжает НИКОГДА.
//
// Отсрочка объяснялась тем, что «RPC не реализован». Утверждение пережило свой
// предмет: use-case существует (`internal_on_recovery.go`) и вызывается по
// внутреннему gRPC; не хватало ровно HTTP-маршрута к нему.
//
// # Что стоит на кону
//
// Восстановление пароля — единственный путь вернуть доступ человеку, потерявшему
// его. Оно обязано: снять блокировку строки пользователя и сдвинуть отсечку, по
// которой отбраковываются прежние сессии. Пока хук не доезжал, обе части не
// происходили: восстановивший доступ оставался заблокированным, а старые сессии
// переживали восстановление — то есть событие, ради которого механизм и нужен,
// не имело последствий.
package iamhooks

import (
	"context"
	"log/slog"
	"net/http"
)

// RecoveryHookConfig — runtime config хука восстановления.
type RecoveryHookConfig struct {
	HookSharedSecret string
}

// RecoveryInput — расшифрованная полезная нагрузка провайдера.
//
// Handler-local DTO: пакет НЕ импортирует use-case — composition root маппит
// это в свой вход. Тот же приём, что у соседних хуков, и по той же причине:
// транспорт не должен тянуть за собой типы бизнес-слоя.
type RecoveryInput struct {
	// ExternalID — идентичность у провайдера (его `identity.id`).
	ExternalID string
	// Email — адрес, по которому шло восстановление.
	Email string
	// RecoveryJTI — идентификатор события восстановления. Нужен для
	// идемпотентности: провайдер вправе повторить доставку, и повтор обязан
	// быть no-op, а не вторым сдвигом отсечки.
	RecoveryJTI string
}

// RecoveryCompleter — узкий порт. Реализуется адаптером из composition root,
// который зовёт use-case завершения восстановления.
type RecoveryCompleter interface {
	CompleteRecovery(ctx context.Context, in RecoveryInput) error
}

// RecoveryHookHandler — HTTP-обработчик.
type RecoveryHookHandler struct {
	cfg       RecoveryHookConfig
	completer RecoveryCompleter
	logger    *slog.Logger
}

// NewRecoveryHookHandler — constructor.
func NewRecoveryHookHandler(
	cfg RecoveryHookConfig,
	completer RecoveryCompleter,
	logger *slog.Logger,
) *RecoveryHookHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &RecoveryHookHandler{cfg: cfg, completer: completer, logger: logger}
}

// kratosRecoveryRequest — полезная нагрузка от провайдера.
//
// Имена полей совпадают с тем, что эмитит шаблон полезной нагрузки, и с формой
// соседнего хука заведения пользователя: расхождение в написании здесь означало
// бы молча пустое поле, а пустой идентификатор восстановления снимает
// идемпотентность.
type kratosRecoveryRequest struct {
	ExternalID  string `json:"external_id"`
	Email       string `json:"email"`
	RecoveryJTI string `json:"recovery_jti"`
}

// ServeHTTP реализует http.Handler.
//
// Порядок отказов тот же, что у соседей, и он не случаен: метод → секрет → тело
// → обязательные поля. Проверка секрета стоит ДО разбора тела, чтобы неизвестный
// отправитель не заставлял нас разбирать его JSON.
func (h *RecoveryHookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if !requireHookAuth(w, r, h.cfg.HookSharedSecret, h.logger, "recovery_hook") {
		return
	}

	var payload kratosRecoveryRequest
	if !decodeHookBody(w, r, &payload, h.logger, "recovery_hook") {
		return
	}
	defer func() { _ = r.Body.Close() }()

	// Обязательные поля проверяются ЗДЕСЬ, а не только в use-case: провайдеру
	// нужен отказ формы (400), а не отказ обработки, иначе он повторит доставку
	// того же неполного события до исчерпания своих попыток.
	if payload.ExternalID == "" {
		h.logger.Warn("recovery_hook: missing external_id in payload")
		http.Error(w, `{"error":"missing_external_id"}`, http.StatusBadRequest)
		return
	}
	if payload.RecoveryJTI == "" {
		h.logger.Warn("recovery_hook: missing recovery_jti in payload",
			"external_id", payload.ExternalID)
		http.Error(w, `{"error":"missing_recovery_jti"}`, http.StatusBadRequest)
		return
	}

	if err := h.completer.CompleteRecovery(r.Context(), RecoveryInput(payload)); err != nil {
		// Причина — в журнал, наружу фиксированный текст: провайдеру различать
		// нечего, а нам различать обязательно (тот же разъезд адресатов, что у
		// выдачи токена).
		h.logger.Error("recovery_hook: completion failed",
			"err", err, "external_id", payload.ExternalID)
		http.Error(w, `{"error":"recovery_completion_failed"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
