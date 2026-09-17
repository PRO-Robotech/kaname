// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package operationresolver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func getPresent(_ context.Context, id domain.RoleID) (domain.Role, error) {
	return domain.Role{ID: id}, nil
}

func getAbsent(_ context.Context, _ domain.RoleID) (domain.Role, error) {
	return domain.Role{}, iamerr.ErrNotFound
}

func marshalTestRole(r domain.Role) (*anypb.Any, error) {
	return anypb.New(&iamv1.Role{Id: string(r.ID)})
}

// TestResolveExistence — ядро orphan-резолюции: для Create/Update ресурс должен
// присутствовать (→ Done+Response), иначе работа не закоммичена (→ Interrupted);
// для Delete отсутствие = успех (→ Done(nil)), присутствие = не завершено
// (→ Interrupted).
func TestResolveExistence(t *testing.T) {
	ctx := context.Background()

	t.Run("create present → Done with response", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindCreate, "rol_1", getPresent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeDone, res.Outcome)
		require.NotNil(t, res.Response, "Done на Create несет текущий ресурс")
	})

	t.Run("create absent → Interrupted", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindCreate, "rol_1", getAbsent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})

	t.Run("update absent → Interrupted", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindUpdate, "rol_1", getAbsent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})

	t.Run("delete absent → Done empty", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindDelete, "rol_1", getAbsent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeDone, res.Outcome)
		require.Nil(t, res.Response, "удаленный ресурс → Empty-семантика")
	})

	t.Run("delete present → Interrupted", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindDelete, "rol_1", getPresent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})
}

// TestResolveExistence_TransientReadError — нераспознанная ошибка чтения (не
// not-found) пробрасывается: движок инкрементит reconcile_errors и пропускает
// orphan до следующего sweep'а, а не «решает» его неверно.
func TestResolveExistence_TransientReadError(t *testing.T) {
	getErr := func(_ context.Context, _ domain.RoleID) (domain.Role, error) {
		return domain.Role{}, context.DeadlineExceeded
	}
	_, err := resolveExistence(context.Background(), kindCreate, "rol_1", getErr, marshalTestRole)
	require.Error(t, err, "transient read error must not be swallowed into a terminal decision")
}

// TestResolve_NilMetadata — операция без метаданных не наша → Skip.
func TestResolve_NilMetadata(t *testing.T) {
	r := New(nil, catalogfixture.Source(), accessKeyReaderStub{})
	res, err := r.Resolve(context.Background(), operations.Operation{ID: "iop_1"})
	require.NoError(t, err)
	require.Equal(t, operations.OutcomeSkip, res.Outcome)
}

// TestResolveMembershipPair — kaname#181: осиротевшее создание членства
// разрешается ПАРОЙ «человек × аккаунт» из метаданных, а не одним
// идентификатором: пара есть → работа закоммичена, ответ — членство той же
// проекцией, что у чтений; пары нет → до коммита не дошло (повтор создания
// идемпотентен по построению — пара уникальна, идентификатор вычислим).
func TestResolveMembershipPair(t *testing.T) {
	ctx := context.Background()
	present := func(_ context.Context, uid domain.UserID, acc domain.AccountID) (domain.Membership, error) {
		return domain.Membership{ID: "mbr-0000000000000pair", UserID: uid, AccountID: acc,
			State: domain.MembershipStateActive}, nil
	}
	absent := func(context.Context, domain.UserID, domain.AccountID) (domain.Membership, error) {
		return domain.Membership{}, iamerr.ErrNotFound
	}
	transient := func(context.Context, domain.UserID, domain.AccountID) (domain.Membership, error) {
		return domain.Membership{}, context.DeadlineExceeded
	}

	t.Run("pair present → Done with the Membership", func(t *testing.T) {
		res, err := resolveMembershipPair(ctx, "usr0000000000000pair", "acc0000000000000pair", present)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeDone, res.Outcome)
		require.NotNil(t, res.Response)
		m := &iamv1.Membership{}
		require.NoError(t, res.Response.UnmarshalTo(m), "ответ — Membership той же проекции")
		require.Equal(t, "mbr-0000000000000pair", m.GetId())
		require.Equal(t, iamv1.Membership_ACTIVE, m.GetState())
	})

	t.Run("pair absent → Interrupted", func(t *testing.T) {
		res, err := resolveMembershipPair(ctx, "usr0000000000000pair", "acc0000000000000pair", absent)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})

	t.Run("transient read error is not a verdict", func(t *testing.T) {
		_, err := resolveMembershipPair(ctx, "usr0000000000000pair", "acc0000000000000pair", transient)
		require.Error(t, err)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Ключи доступа (Ф7, kacho#1273): осиротевшие регистрация и снятие.

type accessKeyReaderStub struct {
	key domain.AccessKey
	ok  bool
	err error
}

func (s accessKeyReaderStub) KeyOwnedByID(context.Context, domain.UserID, domain.AccessKeyID) (domain.AccessKey, bool, error) {
	return s.key, s.ok, s.err
}

// TestResolveAccessKey — регистрация разрешается ПРИСУТСТВИЕМ строки ключа у
// названного человека (есть → Done с ключом той же проекцией, что у чтения;
// нет → Interrupted), снятие — ОТСУТСТВИЕМ (нет → Done с идентификатором; есть
// → Interrupted). Строка ищется парой (человек, ключ): ключ другого человека —
// не наш ключ.
func TestResolveAccessKey(t *testing.T) {
	ctx := context.Background()
	key := domain.AccessKey{ID: "ak-0000000000000key1", UserID: "usr00000000000000001", Name: "laptop", CreatedAt: time.Now()}
	present := accessKeyReaderStub{key: key, ok: true}
	absent := accessKeyReaderStub{}
	transient := accessKeyReaderStub{err: context.DeadlineExceeded}

	t.Run("register, key present → Done with the AccessKey", func(t *testing.T) {
		res, err := resolveAccessKey(ctx, kindCreate, key.UserID, key.ID, present)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeDone, res.Outcome)
		require.NotNil(t, res.Response)
		var resp iamv1.RegisterAccessKeyResponse
		require.NoError(t, res.Response.UnmarshalTo(&resp))
		require.Equal(t, string(key.ID), resp.GetAccessKey().GetId())
		require.Equal(t, "laptop", resp.GetAccessKey().GetName())
	})
	t.Run("register, key absent → Interrupted", func(t *testing.T) {
		res, err := resolveAccessKey(ctx, kindCreate, key.UserID, key.ID, absent)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})
	t.Run("revoke, key absent → Done with the id", func(t *testing.T) {
		res, err := resolveAccessKey(ctx, kindDelete, key.UserID, key.ID, absent)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeDone, res.Outcome)
		var resp iamv1.RevokeAccessKeyResponse
		require.NoError(t, res.Response.UnmarshalTo(&resp))
		require.Equal(t, string(key.ID), resp.GetAccessKeyId())
	})
	t.Run("revoke, key present → Interrupted", func(t *testing.T) {
		res, err := resolveAccessKey(ctx, kindDelete, key.UserID, key.ID, present)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})
	t.Run("transient read error is not a decision", func(t *testing.T) {
		_, err := resolveAccessKey(ctx, kindCreate, key.UserID, key.ID, transient)
		require.Error(t, err)
	})
}

// TestResolve_AccessKeyMetadataReachesItsBranch — оба типа метаданных ключа
// разбираются резолвером (не уходят в ветку по умолчанию): читатель ключей
// провязан конструктором, репозиторий ресурсов на этой ветке не открывается.
func TestResolve_AccessKeyMetadataReachesItsBranch(t *testing.T) {
	key := domain.AccessKey{ID: "ak-0000000000000key1", UserID: "usr00000000000000001", Name: "laptop", CreatedAt: time.Now()}
	r := New(nil, catalogfixture.Source(), accessKeyReaderStub{key: key, ok: true})

	reg, err := anypb.New(&iamv1.RegisterAccessKeyMetadata{UserId: string(key.UserID), AccessKeyId: string(key.ID)})
	require.NoError(t, err)
	res, err := r.Resolve(context.Background(), operations.Operation{ID: "iop_1", Metadata: reg})
	require.NoError(t, err)
	require.Equal(t, operations.OutcomeDone, res.Outcome)

	rev, err := anypb.New(&iamv1.RevokeAccessKeyMetadata{UserId: string(key.UserID), AccessKeyId: string(key.ID)})
	require.NoError(t, err)
	res, err = r.Resolve(context.Background(), operations.Operation{ID: "iop_2", Metadata: rev})
	require.NoError(t, err)
	require.Equal(t, operations.OutcomeInterrupted, res.Outcome, "ключ ещё есть — снятие не состоялось")
}
