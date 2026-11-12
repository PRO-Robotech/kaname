// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

type grantRegistrationGate struct{}

func (grantRegistrationGate) Authorize(context.Context) (string, error) { return "vpc", nil }

type grantRegistrationRecorder struct{ writes int }

func (r *grantRegistrationRecorder) Register(context.Context, registerInput) error {
	r.writes++
	return nil
}
func (r *grantRegistrationRecorder) Unregister(context.Context, unregisterInput) error {
	r.writes++
	return nil
}
func (*grantRegistrationRecorder) RecordRefusal(context.Context, unregisterInput, bool, string) error {
	return nil
}

func requireGrantCoordinateRefusal(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != "permission denied" {
		t.Fatalf("внутренняя координата должна давать непрозрачный отказ: %v", err)
	}
}

// Разрешающие порты доказывают, что отказ даёт именно граница координат.
// Оба RPC дополнены законным входом: полное отключение регистратора не зеленеет.
func TestRegistrationRejectsInternalGrantCoordinates(t *testing.T) {
	for _, typ := range []string{grantcapability.ScopeObjectType, grantcapability.RoleObjectType} {
		cases := []struct{ name, subject, relation, object string }{
			{"owner_object", "user:usr1", "owner", typ + ":coordinate"},
			{"hierarchy_object", "project:prj1", "project", typ + ":coordinate"},
			{"named_object", "probemod_box:box1", "box", typ + ":coordinate"},
			{"named_subject", typ + ":coordinate", "box", "vpc_network:net1"},
		}
		for _, tt := range cases {
			t.Run(typ+"/"+tt.name, func(t *testing.T) {
				rec := &grantRegistrationRecorder{}
				h := &Handler{registrar: rec, regGate: grantRegistrationGate{}}
				_, err := h.RegisterResource(context.Background(), &iamv1.RegisterResourceRequest{SubjectId: tt.subject, Relation: tt.relation, Object: tt.object})
				requireGrantCoordinateRefusal(t, err)
				_, err = h.UnregisterResource(context.Background(), &iamv1.UnregisterResourceRequest{SubjectId: tt.subject, Relation: tt.relation, Object: tt.object})
				requireGrantCoordinateRefusal(t, err)
				if rec.writes != 0 {
					t.Fatalf("управляющая координата дошла до записи: %d", rec.writes)
				}
				_, err = h.RegisterResource(context.Background(), &iamv1.RegisterResourceRequest{SubjectId: "project:prj1", Relation: "project", Object: "vpc_network:net1"})
				if err != nil {
					t.Fatalf("законная регистрация отвергнута: %v", err)
				}
				_, err = h.UnregisterResource(context.Background(), &iamv1.UnregisterResourceRequest{SubjectId: "project:prj1", Relation: "project", Object: "vpc_network:net1"})
				if err != nil || rec.writes != 2 {
					t.Fatalf("законное снятие отвергнуто или не дошло до записи: %v; записей %d", err, rec.writes)
				}
			})
		}
	}
}

func TestNamedPointersRejectInternalGrantCoordinates(t *testing.T) {
	for _, typ := range []string{grantcapability.ScopeObjectType, grantcapability.RoleObjectType} {
		if namedPointerSubjectType(typ) {
			t.Fatalf("внутренняя координата %q принята как родитель ресурса", typ)
		}
	}
	if !namedPointerSubjectType("project") || !namedPointerSubjectType("probemod_box") {
		t.Fatal("законные родители перестали допускаться")
	}
}

func TestProxyPolicyRejectsInternalGrantCoordinates(t *testing.T) {
	for _, typ := range []string{grantcapability.ScopeObjectType, grantcapability.RoleObjectType} {
		requireGrantCoordinateRefusal(t, validateProxyTuple("iam", "user:usr1", "owner", typ+":coordinate"))
		requireGrantCoordinateRefusal(t, validateProxyTuple("vpc", typ+":coordinate", "project", "vpc_network:net1"))
	}
	if err := validateProxyTuple("vpc", "project:prj1", "project", "vpc_network:net1"); err != nil {
		t.Fatalf("законная политика регистрации отвергнута: %v", err)
	}
}
