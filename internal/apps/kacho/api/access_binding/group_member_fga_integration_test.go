// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// group_member_fga_integration_test.go — real-OpenFGA proof of the group-
// membership FGA mirror bug (E-31 + ALL group-based authz). Reuses the
// scope_grant real-FGA harness (startOpenFGA / fgaClient / hierarchyTuples).
//
// THE BUG: a binding on a GROUP subject emits `<obj>#<rel>@group:<gid>#member`
// (tuples.go subjectRef → "group:<id>#member"). For OpenFGA to resolve that
// userset to a concrete principal, a member-tuple `group:<gid>#member@user:<uid>`
// (FGA `group:<gid>` object, relation `member`) MUST exist. AddMember wrote ONLY
// the iam-DB group_members row and emitted NO such FGA tuple, so the userset
// resolved to EMPTY: members got no real access, ExpandAccess found no members.
//
// These tests evaluate the REAL canonical fga_model.fga in a REAL OpenFGA server.
//
//   GM-1  member-tuple on FGA type `group` resolves the binding userset →
//         Check(member, viewer, account) ALLOW. (the fix's positive proof)
//   GM-2  WITHOUT the member-tuple (the bug's state) → Check DENY. (the bug)
//   GM-3  TYPE CONSISTENCY: writing the member-tuple on `iam_group` (the group
//         RESOURCE / object-scope type used by group Create) does NOT resolve
//         the `group:<gid>#member` userset → Check DENY. The member-tuple MUST
//         target `group`, NOT `iam_group` (task point 4).
//   GM-4  symmetric revoke: deleting the member-tuple flips Check back to DENY
//         (RemoveMember semantics).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// groupMemberTuple mirrors the production member-tuple AddMember co-commits:
//
//	user|service_account:<member_id>  →  member  →  group:<group_id>
//
// Object type is `group` (the userset type a group-subject binding points at),
// NOT `iam_group` (the group-resource object-scope type).
func groupMemberTuple(memberType, memberID, groupID string) abrepo.RelationTuple {
	return abrepo.RelationTuple{
		User:     memberType + ":" + memberID,
		Relation: "member",
		Object:   "group:" + groupID,
	}
}

// groupSubjectViewerBinding wires the FGA tuple a GROUP-subject binding emits:
// `account:<acc>#viewer@group:<gid>#member` (subjectRef group sigil).
func groupSubjectViewerBinding(groupID, accountID string) abrepo.RelationTuple {
	return abrepo.RelationTuple{
		User:     "group:" + groupID + "#member",
		Relation: "viewer",
		Object:   "account:" + accountID,
	}
}

func TestIntegration_GroupMember_GM1_MemberTupleResolvesBindingUserset(t *testing.T) {
	c := startOpenFGA(t)
	c.write(t, hierarchyTuples())

	// Binding: group grp_team is viewer on account acc_A.
	c.write(t, []abrepo.RelationTuple{groupSubjectViewerBinding("grp_team", "acc_A")})
	// AddMember(user usr_m1) → the FGA member-tuple on type `group`.
	c.write(t, []abrepo.RelationTuple{groupMemberTuple("user", "usr_m1", "grp_team")})

	assert.True(t,
		c.check(t, "user:usr_m1", "viewer", "account:acc_A"),
		"GM-1: group member must inherit the group-subject binding's viewer grant")
}

func TestIntegration_GroupMember_GM2_NoMemberTuple_Deny(t *testing.T) {
	c := startOpenFGA(t)
	c.write(t, hierarchyTuples())

	// Binding present, but NO member-tuple (the pre-fix bug state).
	c.write(t, []abrepo.RelationTuple{groupSubjectViewerBinding("grp_team", "acc_A")})

	assert.False(t,
		c.check(t, "user:usr_m1", "viewer", "account:acc_A"),
		"GM-2: without the FGA member-tuple the userset is empty → member denied (the bug)")
}

func TestIntegration_GroupMember_GM3_WrongType_iam_group_DoesNotResolve(t *testing.T) {
	c := startOpenFGA(t)
	c.write(t, hierarchyTuples())

	c.write(t, []abrepo.RelationTuple{groupSubjectViewerBinding("grp_team", "acc_A")})
	// Member-tuple written on the WRONG FGA type `iam_group` (the group RESOURCE
	// object-scope type, group Create's hierarchy type) — the binding userset
	// points at `group:grp_team#member`, so this MUST NOT resolve.
	c.write(t, []abrepo.RelationTuple{{
		User:     "user:usr_m1",
		Relation: "member",
		Object:   "iam_group:grp_team",
	}})

	assert.False(t,
		c.check(t, "user:usr_m1", "viewer", "account:acc_A"),
		"GM-3: member-tuple on iam_group must NOT resolve the group:#member userset (type consistency)")
}

func TestIntegration_GroupMember_GM4_RemoveFlipsToDeny(t *testing.T) {
	c := startOpenFGA(t)
	c.write(t, hierarchyTuples())

	c.write(t, []abrepo.RelationTuple{groupSubjectViewerBinding("grp_team", "acc_A")})
	mt := groupMemberTuple("user", "usr_m1", "grp_team")
	c.write(t, []abrepo.RelationTuple{mt})
	require.True(t, c.check(t, "user:usr_m1", "viewer", "account:acc_A"), "precondition: member allowed")

	// RemoveMember symmetric revoke.
	c.delete(t, []abrepo.RelationTuple{mt})
	assert.False(t,
		c.check(t, "user:usr_m1", "viewer", "account:acc_A"),
		"GM-4: after the member-tuple is revoked the member is denied again")
}
