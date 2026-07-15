// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"

	_ "github.com/PRO-Robotech/kacho/services/iam/internal/dto/toproto"
)

// memberFGATuple builds the FGA userset member-tuple a group membership mirrors:
//
//	user|service_account:<member_id>  →  member  →  group:<group_id>
//
// This is the tuple OpenFGA needs to resolve a GROUP-subject AccessBinding's
// `<obj>#<rel>@group:<gid>#member` userset (access_binding/tuples.go subjectRef
// emits `group:<id>#member`) into the concrete member principal. AddMember
// co-commits it (write), RemoveMember co-commits its symmetric delete.
//
// The OBJECT type is `group` — the FGA userset type the binding's subjectRef
// points at (fga_model.fga `type group { define member }`), NOT `iam_group`
// (the group-resource object-scope hierarchy type group Create emits). Writing
// the member-tuple on `iam_group` would NOT resolve the binding userset.
//
// The member_type value ("user" / "service_account") IS the canonical FGA user
// prefix (domain.SubjectType ↔ FGA user namespace), so it maps verbatim — the
// same prefixing access_binding/subjectRef uses for the binding's subject side.
func memberFGATuple(m domain.GroupMember) service.RelationTuple {
	return service.RelationTuple{
		User:     fmt.Sprintf("%s:%s", m.MemberType, m.MemberID),
		Relation: "member",
		Object:   fmt.Sprintf("group:%s", m.GroupID),
	}
}

func marshalGroup(g domain.Group) (*anypb.Any, error) {
	var dst *iamv1.Group
	if err := dto.Transfer(dto.FromTo(g, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer Group: %w", err)
	}
	return anypb.New(dst)
}

func marshalGroupMember(m domain.GroupMember) (*anypb.Any, error) {
	var dst *iamv1.GroupMember
	if err := dto.Transfer(dto.FromTo(m, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer GroupMember: %w", err)
	}
	return anypb.New(dst)
}

func labelsFromProto(m map[string]string) domain.Labels {
	if len(m) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(m))
	for k, v := range m {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}
