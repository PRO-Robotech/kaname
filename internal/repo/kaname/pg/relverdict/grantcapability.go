// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"context"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/jackc/pgx/v5"
)

func isGrantCapabilityType(typ string) bool {
	return grantcapability.IsInternalObjectType(typ)
}

// Ветвь native-источника выбирается допущенным планом модели.
// $1 — говорящий, $2/$3 — точная область, $4 — точная привязываемая роль,
// $5 — время решения; $6/$7 — общие позиции системных классов говорящего.
const grantCapabilitySQL = `WITH {{speaker_pairs}}
capability_source AS (
 SELECT b.id
 FROM speaker_pair sp
 JOIN kaname.access_binding_subjects bs
   ON bs.subject_type=sp.s_type AND bs.subject_id=sp.s_id
  AND bs.resource_type=$2::text AND bs.resource_id=$3::text
 JOIN kaname.access_bindings b ON b.id=bs.binding_id
 JOIN kaname.roles owner ON owner.id=b.role_id AND owner.live
 {{meta_join}}
 WHERE ((sp.via='self' AND sp.s_type IN ('user','service_account'))
        OR (sp.via='member' AND sp.s_type='group'))
   AND ` + speakerExistsSQL + `
   AND b.resource_type=$2::text AND b.resource_id=$3::text
   AND b.status='ACTIVE' AND b.revoked_at IS NULL
   AND b.grant_capability_version=1
   AND (b.expires_at IS NULL OR b.expires_at > $5::timestamptz)
   AND (` + wholeScopeTarget + `)
)
SELECT EXISTS(SELECT 1 FROM capability_source)`

func askGrantCapability(ctx context.Context, tx pgx.Tx, in Query) (Verdict, Grounds, error) {
	g := Grounds{}
	plans := in.PreparedPlans
	if plans == nil {
		var err error
		plans, err = authzmodel.Shared()
		if err != nil {
			return Unknown, g, err
		}
	}
	if err := plans.GrantCapabilityPlan(in.ObjectType, in.Relation); err != nil {
		return Unknown, g, err
	}
	coordinate, err := grantcapability.Decode(grantcapability.Reference{ObjectType: in.ObjectType, ObjectID: in.ObjectID, Relation: in.Relation})
	if err != nil {
		return Unknown, g, err
	}
	if in.DecisionAt.IsZero() {
		return Unknown, g, fmt.Errorf("relverdict: grant capability requires explicit decision time")
	}
	if tx == nil {
		return Unknown, g, fmt.Errorf("relverdict: grant capability transaction absent")
	}
	join := "JOIN kaname.role_create_binding_rule meta ON meta.role_id=owner.id"
	if coordinate.Kind == domain.GrantCapabilityBindRole {
		join = "JOIN kaname.role_bind_role_rule meta ON meta.role_id=owner.id AND meta.bound_role_id=$4::text JOIN kaname.roles referent ON referent.id=meta.bound_role_id AND referent.live"
	} else {
		// У каждого параметра есть тип и в форме создания привязки.
		join += " AND $4::text=''"
	}
	sql := strings.Replace(grantCapabilitySQL, "{{meta_join}}", join, 1)
	speakers := strings.NewReplacer("$10", "$6", "$11", "$7").Replace(directSpeakerPairsSQL)
	sql = strings.Replace(sql, "{{speaker_pairs}}", speakers, 1)
	var allowed bool
	err = tx.QueryRow(ctx, sql, in.Subject, coordinate.Anchor.Type, coordinate.Anchor.ID, string(coordinate.RoleID), in.DecisionAt,
		classSlot(in.Subject, 0), classSlot(in.Subject, 1)).Scan(&allowed)
	if err != nil {
		return Unknown, g, fmt.Errorf("relverdict: grant capability source: %w", err)
	}
	g.SetExhausted = !allowed
	if allowed {
		return Allow, g, nil
	}
	return Deny, g, nil
}
