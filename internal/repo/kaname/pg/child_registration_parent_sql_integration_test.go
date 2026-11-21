// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// authorityTestDB устанавливает штатные функции миграций. Входные образы
// построены в форме захвата, чтобы отдельно проверить решение PostgreSQL
// о кортеже на выбранном родителе.
func TestChildRegistrationParentSQL_ZeroChildrenExactAndClosed(t *testing.T) {
	ctx, db, _ := authorityTestDB(t)
	encode := func(value any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		return raw
	}
	for _, catalogVerb := range []string{"registerchild", "registerChild"} {
		t.Run(catalogVerb, func(t *testing.T) {
			halves := catalog.Halves{Live: catalog.Rows{
				Modules: []string{"probe"},
				Resources: []catalog.ResourceRow{
					{Module: "probe", Resource: "boxes", ObjectType: "odd_box"},
					{Module: "probe", Resource: "items", ObjectType: "odd_item",
						ParentNames: []string{"parent"}, ParentTypes: []string{"odd_box"},
						ChildRegistration: &catalog.ChildRegistrationRule{
							Verb: "registerchild", ParentSegments: 1, MaxChildren: 8, MaxCreates: 2, WindowSeconds: 60,
						}},
				},
				Verbs: []catalog.VerbRow{
					{Module: "probe", Resource: "boxes", Verb: "get", PerObject: true},
					{Module: "probe", Resource: "items", Verb: catalogVerb,
						ContainerParent: "odd_box", ContainerRelation: "child_registrar"},
				},
			}}
			facts, err := catalog.NewFacts(halves)
			require.NoError(t, err)
			catalogJSON, err := catalog.CanonicalJSON(halves)
			require.NoError(t, err)
			// Роль выбирает родителя и отдельно даёт действие создания потомка.
			// Сам потомок ещё не создан.
			rules := domain.Rules{{Module: "probe", Resources: []string{"boxes"}, Verbs: []string{"get"},
				Children: []domain.Rule{{Resources: []string{"items"}, Verbs: []string{"registerChild"}}},
			}}
			require.NoError(t, rules.Validate(domain.TenantPolicy(), facts))
			rulesJSON, err := domain.EncodeRules(rules)
			require.NoError(t, err)
			selectors := rules.MaterializingSelectors()
			require.Len(t, selectors, 2)
			binding := resourceeffect.ObjectBinding{
				BindingID: "acb_parent", RoleID: "rol_parent", Active: true,
				Scope:  domain.ScopeAnchor{Type: "account", ID: "account_one"},
				Policy: domain.TenantPolicy(), Selectors: selectors,
				Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "u"}},
				Target:   domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.boxes", ID: "one"}}},
			}
			parent := domain.MirrorObject{ObjectType: "probe.boxes", ObjectID: "one",
				ParentAccountIDs: []string{"account_one"}, Labels: map[string]string{"team": "red"}}
			desired, err := resourceeffect.CompileObjectDesired(facts, binding, parent, nil)
			require.NoError(t, err)
			require.Len(t, desired, 2)
			var ordinary, registration resourceeffect.ObjectDesiredMember
			for _, member := range desired {
				switch member.Derivation {
				case "ordinary":
					ordinary = member
				case "child_registration":
					registration = member
				}
			}
			require.Equal(t, "ordinary", ordinary.Derivation)
			require.Equal(t, "child_registration", registration.Derivation)
			require.Equal(t, []domain.MembershipTuple{{User: "user:u", Relation: "child_registrar", Object: "odd_box:one"}}, registration.Tuples)

			var sources []map[string]any
			capture := func(kind int, typ, id string, rows ...map[string]any) {
				states := make([]string, 0, len(rows))
				for _, row := range rows {
					states = append(states, string(encode([]any{"1", "(0,1)", row})))
				}
				sources = append(sources, map[string]any{"kind": kind, "type": typ, "id": id, "projection": "", "states": states})
			}
			capture(8, "binding", "acb_parent", map[string]any{
				"id": "acb_parent", "role_id": "rol_parent", "status": "ACTIVE",
				"subject_type": "user", "subject_id": "u", "resource_type": "account", "resource_id": "account_one",
				"scope": int(domain.ScopeAccount), "target": binding.Target,
			})
			capture(9, "binding", "acb_parent") // Используется основной субъект выдачи.
			capture(12, "role", "rol_parent", map[string]any{
				"id": "rol_parent", "live": true, "is_system": false, "cluster_id": nil, "owner_module": nil,
				"rules": json.RawMessage(rulesJSON),
			})
			var selectorRows []map[string]any
			for _, selector := range selectors {
				row := map[string]any{"role_id": "rol_parent", "rule_fp": selector.RuleFP, "object_types": selector.ObjectTypes}
				if selector.Container != nil {
					row["container_type"] = selector.Container.Type
				}
				selectorRows = append(selectorRows, row)
			}
			capture(13, "role", "rol_parent", selectorRows...)
			for _, id := range []string{"one", "two"} {
				capture(2, "probe.boxes", id, map[string]any{
					"object_type": "probe.boxes", "object_id": id,
					"parent_account_id": "account_one", "parent_project_id": "", "labels": parent.Labels,
				})
				capture(3, "odd_box", id)
			}
			// Для доказательства достаточно захваченного живого родителя.
			// Ни зеркала потомка, ни захвата его ветви ещё нет.
			sourceJSON := encode(sources)
			verify := func(id string, members []resourceeffect.ObjectDesiredMember) ([]byte, error) {
				var certificate []byte
				err := db.QueryRow(ctx, `WITH i AS (
 SELECT kaname._authority_resource_capture_index_v2($1::jsonb,100000) idx
), p AS (
 SELECT idx,kaname._authority_resource_projection_v2(idx,'probe.boxes',$4) graph FROM i
), g AS (
 SELECT idx,graph||jsonb_build_object('ancestors',
  kaname._authority_resource_ancestor_graph_v2(idx,$2::jsonb,graph)->'ancestors') graph FROM p
)
SELECT kaname._authority_resource_coordinate_certificate_v2(idx,$2::jsonb,$3,graph,$5::jsonb) FROM g`,
					sourceJSON, catalogJSON, "acb_parent", id, encode(members)).Scan(&certificate)
				return certificate, err
			}
			certificate, err := verify("one", desired)
			require.NoError(t, err)
			var result struct {
				Desired []resourceeffect.ObjectDesiredMember `json:"desired"`
			}
			require.NoError(t, json.Unmarshal(certificate, &result))
			require.Equal(t, desired, result.Desired)

			_, err = verify("one", []resourceeffect.ObjectDesiredMember{ordinary})
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "42501", pgErr.Code)
			require.Contains(t, pgErr.Message, "unproven special member absence")

			wrong := registration
			wrong.ObjectID = "two"
			wrong.Tuples = []domain.MembershipTuple{{User: "user:u", Relation: "child_registrar", Object: "odd_box:two"}}
			_, err = verify("two", []resourceeffect.ObjectDesiredMember{wrong}) // Область та же, цель другая.
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "42501", pgErr.Code)
			require.Contains(t, pgErr.Message, "special member status or fingerprint mismatch")
			_, err = verify("two", []resourceeffect.ObjectDesiredMember{})
			require.NoError(t, err)
		})
	}
}
