// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// register_resource_errormap_test.go — закрепление преобразования ошибок обработчика
// для RPC прокси FGA RegisterResource / UnregisterResource (аудит r6, утечка/MEDIUM).
//
// emit() сценария возвращает голые fmt.Errorf("begin tx: %w", err) /
// "upsert resource mirror" / "commit", оборачивая сырые ошибки pgx. До исправления
// обработчик возвращал их дословно: gRPC codes.Unknown с полным текстом драйвера
// pgx (host/port/user/db). Эти тесты закрепляют НАБЛЮДАЕМОЕ поведение:
// - ошибка без типизированного признака → codes.Internal с фиксированным непрозрачным "internal error"
// (никогда codes.Unknown и никогда сырой текст pgx), инвариант усиления №1;
// - признак iamerr.ErrUnavailable → codes.Unavailable (повторяемый закрытый отказ);
// - статус ошибки проверки InvalidArgument проходит без изменений.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
)

// failBeginTxBeginner отказывает при получении соединения (Begin), имитируя
// недоступность базы. Текст несёт детали драйвера pgx, которые никогда не должны попасть
// к вызывающему.
type failBeginTxBeginner struct{ err error }

func (b failBeginTxBeginner) Begin(context.Context) (service.Tx, error) { return nil, b.err }

// TestRegisterResourceUseCase_BeginFailure_MapsUnavailable — закрепление первопричины:
// недоступность хранилища на tx.Begin должна проявиться типизированным признаком iamerr.ErrUnavailable,
// а не голым fmt.Errorf, чтобы обработчик перевёл её в повторяемый
// codes.Unavailable с непрозрачным сообщением без утечки текста драйвера pgx.
func TestRegisterResourceUseCase_BeginFailure_MapsUnavailable(t *testing.T) {
	uc := NewRegisterResourceUseCase(
		smEmitter{}, mirrorAdapter{},
		failBeginTxBeginner{err: errors.New("failed to connect to `host=iamdb port=5432 user=kaname`: connection refused")},
		seededCatalogTypes{},
		&recordingPublisher{},
		&recordingWithdrawal{},
		noAudit{},
		unitScopes(),
	).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "vpc"})

	err := uc.Register(context.Background(), &regReq{
		subject: "user:usr_x", relation: "owner", object: "vpc_network:enp_1",
	})
	require.Error(t, err)
	require.ErrorIs(t, err, iamerr.ErrUnavailable, "backend-down must carry the retriable sentinel")

	mapped := shared.MapRepoErr(err)
	assert.Equal(t, codes.Unavailable, status.Code(mapped))
	msg := status.Convert(mapped).Message()
	assert.NotContains(t, msg, "connection refused", "must not leak pgx driver text")
	assert.NotContains(t, msg, "host=", "must not leak DB host")
}

// fakeRegistrar реализует порт resourceRegistrar. Оба метода возвращают
// настроенную ошибку дословно, имитируя сырой отказ emit() сценария.
type fakeRegistrar struct {
	registerErr   error
	unregisterErr error
	refusalErr    error
}

func (f *fakeRegistrar) RecordRefusal(context.Context, unregisterInput, bool, string) error {
	return f.refusalErr
}

func (f *fakeRegistrar) Register(_ context.Context, _ registerInput) error {
	return f.registerErr
}

func (f *fakeRegistrar) Unregister(_ context.Context, _ unregisterInput) error {
	return f.unregisterErr
}

// rawPgxErr имитирует отказ соединения pgx, обёрнутый голым fmt.Errorf, — ровно
// форму emit() при отказе базы. Его текст несёт детали драйвера, которые
// НИКОГДА не должны попасть к вызывающему.
var rawPgxErr = errors.New("begin tx: failed to connect to `host=iamdb port=5432 user=kaname database=kaname`: connection refused")

func registrarErrorCases() []struct {
	name    string
	err     error
	want    codes.Code
	wantMsg string // точное непрозрачное сообщение, если непусто (защита от утечки)
} {
	return []struct {
		name    string
		err     error
		want    codes.Code
		wantMsg string
	}{
		// Защита от утечки: ошибка pgx без признака → непрозрачный Internal, никогда Unknown,
		// никогда не возвращает host/port/user/db.
		{"raw pgx — opaque Internal", rawPgxErr, codes.Internal, "internal error"},
		// Недоступность хранилища → повторяемый Unavailable по типизированному признаку.
		{"unavailable sentinel", iamerr.Wrapf(iamerr.ErrUnavailable, "fga proxy backend unavailable"), codes.Unavailable, ""},
		// Статус ошибки проверки проходит без изменений.
		{"invalid-arg passthrough", shared.InvalidArg("labels", "too many labels (max 64)"), codes.InvalidArgument, ""},
	}
}

func newRegistrarHandler(reg resourceRegistrar) *Handler {
	// Проба преобразования использует явную допустимую личность модуля для кортежа vpc.
	return NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithResourceRegistrar(reg, &fakeGate{domain: "vpc"})
}

func TestInternalIAM_RegisterResource_ErrorMapping(t *testing.T) {
	for _, tc := range registrarErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegistrarHandler(&fakeRegistrar{registerErr: tc.err})

			_, err := h.RegisterResource(context.Background(), &iamv1.RegisterResourceRequest{
				SubjectId: "user:usr_x", Relation: "owner", Object: "vpc_network:enp_1",
			})
			require.Error(t, err)
			assert.Equal(t, tc.want, status.Code(err))
			assert.NotEqual(t, codes.Unknown, status.Code(err),
				"raw use-case error must be mapped, never leak as codes.Unknown")
			msg := status.Convert(err).Message()
			assert.NotContains(t, msg, "connection refused", "must not leak pgx driver text")
			assert.NotContains(t, msg, "host=", "must not leak DB host")
			assert.NotContains(t, msg, "kaname", "must not leak DB user/name")
			if tc.wantMsg != "" {
				assert.Equal(t, tc.wantMsg, msg)
			}
		})
	}
}

func TestInternalIAM_UnregisterResource_ErrorMapping(t *testing.T) {
	for _, tc := range registrarErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegistrarHandler(&fakeRegistrar{unregisterErr: tc.err})

			_, err := h.UnregisterResource(context.Background(), &iamv1.UnregisterResourceRequest{
				SubjectId: "user:usr_x", Relation: "owner", Object: "vpc_network:enp_1",
			})
			require.Error(t, err)
			assert.Equal(t, tc.want, status.Code(err))
			assert.NotEqual(t, codes.Unknown, status.Code(err),
				"raw use-case error must be mapped, never leak as codes.Unknown")
			msg := status.Convert(err).Message()
			assert.NotContains(t, msg, "connection refused", "must not leak pgx driver text")
			assert.NotContains(t, msg, "host=", "must not leak DB host")
			assert.NotContains(t, msg, "kaname", "must not leak DB user/name")
			if tc.wantMsg != "" {
				assert.Equal(t, tc.wantMsg, msg)
			}
		})
	}
}

// TestValidateRelationString_RejectsSecondColon — аудит r6 (читаемость/LOW):
// контракт validateRelationString и деление objectType() по первому двоеточию предполагают
// ровно одно ':'. Объект с двумя двоеточиями молча проходил проверку, а затем objectType()
// делил по ПЕРВОМУ, отчего ключ зеркала/согласования расходился со строкой объекта кортежа
// FGA. Закрепляем документированную грамматику одного двоеточия.
func TestValidateRelationString_RejectsSecondColon(t *testing.T) {
	twoColon := []string{
		"compute_instance:a:b",
		"vpc_network:enp_1:extra",
		"user:usr_x:tail",
	}
	for _, v := range twoColon {
		t.Run(v, func(t *testing.T) {
			err := validateRelationString("object", v)
			require.Error(t, err, "a two-colon object must be rejected")
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}

	// Правильная форма с одним двоеточием по-прежнему проходит.
	for _, v := range []string{"vpc_network:enp_1", "user:usr_x", "compute_instance:cmp_z"} {
		t.Run("valid_"+v, func(t *testing.T) {
			require.NoError(t, validateRelationString("object", v))
		})
	}
}
