// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Ворота меняют только решение о праве; личность по сертификату та же.
type auditOutcomeGate struct{ code codes.Code }

func (g auditOutcomeGate) Authorize(context.Context) (string, error) {
	if g.code != codes.OK {
		return "", status.Error(g.code, "permission denied")
	}
	return "registry", nil
}

func auditOutcomeHandler(w *urxWorld, code codes.Code) *internaliam.Handler {
	return internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithResourceRegistrar(w.reg, auditOutcomeGate{code: code})
}

// Чтение по ключу объекта исключает события посева и проверяет ровно одну строку.
func registrationOutcomePayload(t *testing.T, w *urxWorld, eventType, objectID string) map[string]any {
	t.Helper()
	rows, err := w.pool.Query(w.ctx, `SELECT event_payload FROM kaname.audit_outbox
		WHERE event_type=$1 AND event_payload #>> '{object,id}'=$2`, eventType, objectID)
	require.NoError(t, err)
	defer rows.Close()
	var payloads []map[string]any
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var p map[string]any
		require.NoError(t, json.Unmarshal(raw, &p))
		payloads = append(payloads, p)
	}
	require.NoError(t, rows.Err())
	require.Len(t, payloads, 1, "kaname#1044: один исход — одно событие")
	return payloads[0]
}

// Сравнивается сохранённая строка целиком, включая версию и updated_at.
// Версия запроса имеет наносекунды, а PostgreSQL хранит микросекунды: сравнение
// запроса с БД не доказывает, что отказ изменил состояние.
func registrationMirrorSnapshot(t *testing.T, w *urxWorld) string {
	t.Helper()
	var snapshot string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT to_jsonb(m)::text FROM kaname.resource_mirror m
		WHERE object_type=$1 AND object_id=$2`, pcrRegTgt, auditK).Scan(&snapshot))
	return snapshot
}

func assertRegistrationCaller(t *testing.T, p map[string]any, outcome string) {
	t.Helper()
	assert.Equal(t, "service_account:"+authzguard.ServiceAccountIDForService("registry"), p["actor"])
	assert.Equal(t, "registry", p["module"])
	assert.Equal(t, outcome, p["outcome"])
}

// Родитель не прислан: полная цепь события выводится из данных kaname (kaname#982).
func TestRegistrationAudit1044_DerivedParentAndVersion(t *testing.T) {
	w := newURXWorld(t)
	id := pcrX + "/audit1044"
	r := &iamv1.RegisterResourceRequest{
		SubjectId: pcrRegType + ":" + pcrX, Relation: "parent", Object: pcrRepoType + ":" + id,
		SourceVersion: w.nextVersion(),
	}
	h := auditOutcomeHandler(w, codes.OK)
	_, err := h.RegisterResource(registryModuleCtx(), r)
	require.NoError(t, err, "законный близнец: регистрация без подсказок родителя")
	check := func(t *testing.T, eventType, outcome, version string) {
		p := registrationOutcomePayload(t, w, eventType, id)
		assertRegistrationCaller(t, p, outcome)
		assert.Equal(t, map[string]any{"type": "registry.repositories", "id": id}, p["object"])
		assert.Equal(t, map[string]any{"type": pcrRegType, "id": pcrX}, p["parent"])
		assert.Equal(t, []any{pcrRegType + ":" + pcrX, "project:" + string(w.prjA), "account:" + string(w.accA)}, p["parent_chain"])
		assert.Equal(t, version, p["source_version"])
	}
	t.Run("register", func(t *testing.T) {
		check(t, auditRegistered, "registered", r.SourceVersion.AsTime().UTC().Format(time.RFC3339Nano))
	})
	_, err = h.RegisterResource(registryModuleCtx(), r)
	require.NoError(t, err)
	registrationOutcomePayload(t, w, auditRegistered, id)
	u := &iamv1.UnregisterResourceRequest{SubjectId: r.SubjectId, Relation: r.Relation, Object: r.Object, SourceVersion: w.nextVersion()}
	_, err = h.UnregisterResource(registryModuleCtx(), u)
	require.NoError(t, err)
	t.Run("unregister", func(t *testing.T) {
		check(t, auditUnregistered, "unregistered", u.SourceVersion.AsTime().UTC().Format(time.RFC3339Nano))
	})
}

func TestRegistrationAudit1044_PermissionDenied(t *testing.T) {
	for _, unregister := range []bool{false, true} {
		name := "register"
		if unregister {
			name = "unregister"
		}
		t.Run(name, func(t *testing.T) {
			w := newURXWorld(t)
			r := auditKRequest(w)
			// Законный близнец тем же обработчиком и сертификатом проходит.
			_, err := auditOutcomeHandler(w, codes.OK).RegisterResource(registryModuleCtx(), r)
			require.NoError(t, err)
			_, err = w.pool.Exec(w.ctx, `DELETE FROM kaname.audit_outbox WHERE event_payload #>> '{object,id}'=$1`, auditK)
			require.NoError(t, err)
			h := auditOutcomeHandler(w, codes.PermissionDenied)
			eventType := auditRegistered
			if unregister {
				eventType = auditUnregistered
				_, err = h.UnregisterResource(registryModuleCtx(), &iamv1.UnregisterResourceRequest{
					SubjectId: r.SubjectId, Relation: r.Relation, Object: r.Object, SourceVersion: r.SourceVersion})
			} else {
				_, err = h.RegisterResource(registryModuleCtx(), r)
			}
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			p := registrationOutcomePayload(t, w, eventType, auditK)
			assertRegistrationCaller(t, p, "permission_denied")
			assert.Equal(t, r.SourceVersion.AsTime().UTC().Format(time.RFC3339Nano), p["source_version"])
		})
	}
}

func TestRegistrationAudit1044_FailedPrecondition(t *testing.T) {
	w := newURXWorld(t)
	r := auditKRequest(w)
	h := auditOutcomeHandler(w, codes.OK)
	_, err := h.RegisterResource(registryModuleCtx(), r)
	require.NoError(t, err, "законный близнец: область согласна")
	_, err = w.pool.Exec(w.ctx, `DELETE FROM kaname.audit_outbox WHERE event_payload #>> '{object,id}'=$1`, auditK)
	require.NoError(t, err)
	// Единственная дельта — аккаунт, не совпадающий с аккаунтом проекта.
	r.ParentAccountId = string(w.accB)
	_, err = h.RegisterResource(registryModuleCtx(), r)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	p := registrationOutcomePayload(t, w, auditRegistered, auditK)
	assertRegistrationCaller(t, p, "failed_precondition")
	assert.NotEqual(t, string(w.accB), p["parent_account_id"], "отказ не объявляет присланную область истиной")
}

// Неподтверждённый SAN не объявляется личностью модуля даже в событии отказа.
func TestRegistrationAudit1044_UnverifiedCertificateIsNotCaller(t *testing.T) {
	w := newURXWorld(t)
	r := auditKRequest(w)
	_, err := auditOutcomeHandler(w, codes.OK).RegisterResource(registryModuleCtx(), r)
	require.NoError(t, err, "подтверждённый близнец: личность модуля в событии")
	assertRegistrationCaller(t, registrationOutcomePayload(t, w, auditRegistered, auditK), "registered")
	before := registrationMirrorSnapshot(t, w)
	t.Logf("Точность фикстуры: request source_version=%s; persisted mirror=%s", r.SourceVersion.AsTime().UTC().Format(time.RFC3339Nano), before)
	r.SourceVersion = w.nextVersion()
	_, err = w.pool.Exec(w.ctx, `DELETE FROM kaname.audit_outbox WHERE event_payload #>> '{object,id}'=$1`, auditK)
	require.NoError(t, err)
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-registry", false)
	_, err = auditOutcomeHandler(w, codes.PermissionDenied).RegisterResource(ctx, r)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Zero(t, w.auditRows(auditRegistered), "неподтверждённый SAN не порождает событие модуля")
	assert.Equal(t, before, registrationMirrorSnapshot(t, w), "отказ не изменил регистрацию")
}

// Настоящая auditTX не фиксируется: исход становится opaque Internal, состояние
// объекта остаётся прежним и событие не объявляется сохранённым.
func TestRegistrationAudit1044_RefusalAuditFailureIsOpaque(t *testing.T) {
	w := newURXWorld(t)
	r := auditKRequest(w)
	h := auditOutcomeHandler(w, codes.OK)
	_, err := h.RegisterResource(registryModuleCtx(), r)
	require.NoError(t, err)
	_, err = w.pool.Exec(w.ctx, `DELETE FROM kaname.audit_outbox WHERE event_payload #>> '{object,id}'=$1`, auditK)
	require.NoError(t, err)
	_, err = w.pool.Exec(w.ctx, `CREATE FUNCTION kaname.audit1044_fault() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN IF NEW.event_payload #>> '{object,id}' = 'reg00000000000000008' THEN
	RAISE EXCEPTION 'host=secret-audit-db user=private-auditor'; END IF; RETURN NEW; END $$;
	CREATE TRIGGER audit1044_fault BEFORE INSERT ON kaname.audit_outbox FOR EACH ROW EXECUTE FUNCTION kaname.audit1044_fault()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := w.pool.Exec(context.Background(), `DROP TRIGGER audit1044_fault ON kaname.audit_outbox; DROP FUNCTION kaname.audit1044_fault()`)
		assert.NoError(t, cleanupErr)
	})
	before := registrationMirrorSnapshot(t, w)
	t.Logf("Точность фикстуры: request source_version=%s; persisted mirror=%s", r.SourceVersion.AsTime().UTC().Format(time.RFC3339Nano), before)
	for _, operation := range []string{"register_denied", "unregister_denied", "register_precondition"} {
		t.Run(operation, func(t *testing.T) {
			r.SourceVersion = w.nextVersion()
			denied := auditOutcomeHandler(w, codes.PermissionDenied)
			var refusal error
			switch operation {
			case "register_denied":
				_, refusal = denied.RegisterResource(registryModuleCtx(), r)
			case "unregister_denied":
				_, refusal = denied.UnregisterResource(registryModuleCtx(), &iamv1.UnregisterResourceRequest{
					SubjectId: r.SubjectId, Relation: r.Relation, Object: r.Object, SourceVersion: r.SourceVersion})
			case "register_precondition":
				mismatch := auditKRequest(w)
				mismatch.ParentAccountId = string(w.accB)
				_, refusal = h.RegisterResource(registryModuleCtx(), mismatch)
			}
			assert.Equal(t, codes.Internal, status.Code(refusal))
			assert.Equal(t, "internal error", status.Convert(refusal).Message())
			assert.Zero(t, w.auditRows(auditRegistered))
			assert.Zero(t, w.auditRows(auditUnregistered))
			assert.Equal(t, before, registrationMirrorSnapshot(t, w), "неудача аудита не изменила объект")
		})
	}
}
