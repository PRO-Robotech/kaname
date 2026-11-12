// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// Проверки native-читателя на настоящей базе pgtest с миграциями.
// SQL-фикстуры проекций и версий не доказывают выдачу через API или протокол писателей.
import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

func capabilityFixture(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	seedTenant(t, ctx, tx)
	exec(t, ctx, tx, `INSERT INTO kaname.service_accounts(id,account_id,name) VALUES ('sva-cap','acc-1','cap')`)
	exec(t, ctx, tx, `INSERT INTO kaname.groups(id,account_id,name) VALUES ('grp-cap','acc-1','cap')`)
	exec(t, ctx, tx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES ('grp-cap','user','usr-1')`)
	exec(t, ctx, tx, `INSERT INTO kaname.roles(id,account_id,name,permissions,rules) VALUES
 ('rol-cap-owner','acc-1','cap_owner','[]','[{"module":"iam","resources":["accessBinding"],"verbs":["create"]},{"module":"iam","resources":["role"],"verbs":["bind"],"resource_names":["rol-cap-target"]}]'),
 ('rol-cap-target','acc-1','cap_target','[]','[{"module":"iam","resources":["role"],"verbs":["get"]}]'),
 ('rol-cap-other','acc-1','cap_other','[]','[{"module":"iam","resources":["role"],"verbs":["get"]}]')`)
	exec(t, ctx, tx, `INSERT INTO kaname.role_create_binding_rule(role_id,rule_fp) VALUES ('rol-cap-owner',$1)`, strings.Repeat("a", 64))
	exec(t, ctx, tx, `INSERT INTO kaname.role_bind_role_rule(role_id,rule_fp,bound_role_id) VALUES ('rol-cap-owner',$1,'rol-cap-target')`, strings.Repeat("b", 64))
	capabilityCarrier(t, ctx, tx, "acb-cap-one", "user", "usr-1")
}

func capabilityCarrier(t *testing.T, ctx context.Context, tx pgx.Tx, id, typ, subject string) {
	capabilityCarrierAt(t, ctx, tx, id, typ, subject, "project", "prj-1")
}

func capabilityCarrierAt(t *testing.T, ctx context.Context, tx pgx.Tx, id, typ, subject, anchorType, anchorID string) {
	t.Helper()
	exec(t, ctx, tx, `INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status,created_at,grant_capability_version)
 VALUES ($1,$2,$3,'rol-cap-owner',$4,$5,'ACTIVE','2000-01-01',1)`, id, typ, subject, anchorType, anchorID)
	exec(t, ctx, tx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) VALUES($1,$2,$3)`, id, typ, subject)
}

func capabilityQuestion(t *testing.T, typ, id, role string) relverdict.Query {
	t.Helper()
	c := grantcapability.Coordinate{Kind: domain.GrantCapabilityCreateBinding, Anchor: domain.ScopeAnchor{Type: typ, ID: id}}
	if role != "" {
		c.Kind = domain.GrantCapabilityBindRole
		c.RoleID = domain.RoleID(role)
	}
	ref, err := grantcapability.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	return relverdict.Query{Subject: "user:usr-1", ObjectType: ref.ObjectType, ObjectID: ref.ObjectID, Relation: ref.Relation, DecisionAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func capabilityWant(t *testing.T, ctx context.Context, tx pgx.Tx, q relverdict.Query, want relverdict.Verdict) {
	t.Helper()
	got, _, err := relverdict.Ask(ctx, tx, q)
	if err != nil || got != want {
		t.Fatalf("capability verdict=%v want=%v err=%v", got, want, err)
	}
}

func TestGrantCapabilityNativeExactAxesAndSubjects(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		capabilityFixture(t, ctx, tx)
		for _, role := range []string{"", "rol-cap-target"} {
			capabilityWant(t, ctx, tx, capabilityQuestion(t, "project", "prj-1", role), relverdict.Allow)
			for _, anchor := range [][2]string{{"project", "prj-2"}, {"account", "acc-1"}, {"account", "acc-2"}, {"cluster", "cluster_root"}} {
				capabilityWant(t, ctx, tx, capabilityQuestion(t, anchor[0], anchor[1], role), relverdict.Deny)
			}
		}
		capabilityWant(t, ctx, tx, capabilityQuestion(t, "project", "prj-1", "rol-cap-owner"), relverdict.Deny)
		capabilityWant(t, ctx, tx, capabilityQuestion(t, "project", "prj-1", "rol-cap-other"), relverdict.Deny)
		// Учитываются все субъекты привязки, включая отсутствующего в прежней первой паре.
		exec(t, ctx, tx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) VALUES ('acb-cap-one','service_account','sva-cap')`)
		for _, role := range []string{"", "rol-cap-target"} {
			q := capabilityQuestion(t, "project", "prj-1", role)
			q.Subject = "service_account:sva-cap"
			capabilityWant(t, ctx, tx, q, relverdict.Allow)
		}
		exec(t, ctx, tx, `DELETE FROM kaname.access_binding_subjects WHERE binding_id='acb-cap-one'`)
		exec(t, ctx, tx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) VALUES ('acb-cap-one','group','grp-cap')`)
		for _, role := range []string{"", "rol-cap-target"} {
			capabilityWant(t, ctx, tx, capabilityQuestion(t, "project", "prj-1", role), relverdict.Allow)
		}
		exec(t, ctx, tx, `DELETE FROM kaname.group_members WHERE group_id='grp-cap'`)
		for _, role := range []string{"", "rol-cap-target"} {
			q := capabilityQuestion(t, "project", "prj-1", role)
			capabilityWant(t, ctx, tx, q, relverdict.Deny)
			q.Subject = "group:grp-cap"
			capabilityWant(t, ctx, tx, q, relverdict.Deny)
		}
	})
}

func TestGrantCapabilityNativeAccountAndClusterCarriersAreExact(t *testing.T) {
	for _, anchor := range [][2]string{{"account", "acc-1"}, {"cluster", "cluster_root"}} {
		t.Run(anchor[0], func(t *testing.T) {
			withTx(t, func(ctx context.Context, tx pgx.Tx) {
				capabilityFixture(t, ctx, tx)
				exec(t, ctx, tx, `DELETE FROM kaname.access_bindings WHERE id='acb-cap-one'`)
				if anchor[0] == "cluster" {
					// Кластерный носитель использует настоящие системные роли;
					// аккаунтная роль не подменяет глобальную assignability.
					exec(t, ctx, tx, `INSERT INTO kaname.clusters(id,name) VALUES('cluster_root','cap-cluster') ON CONFLICT DO NOTHING`)
					exec(t, ctx, tx, `UPDATE kaname.roles SET account_id=NULL, cluster_id='cluster_root',
					    name=CASE id WHEN 'rol-cap-owner' THEN 'cap.owner' ELSE 'cap.target' END
					    WHERE id IN ('rol-cap-owner','rol-cap-target')`)
				}
				capabilityCarrierAt(t, ctx, tx, "acb-cap-anchor", "user", "usr-1", anchor[0], anchor[1])
				for _, role := range []string{"", "rol-cap-target"} {
					capabilityWant(t, ctx, tx, capabilityQuestion(t, anchor[0], anchor[1], role), relverdict.Allow)
					for _, other := range [][2]string{{"project", "prj-1"}, {"account", "acc-2"}} {
						capabilityWant(t, ctx, tx, capabilityQuestion(t, other[0], other[1], role), relverdict.Deny)
					}
					if anchor[0] == "cluster" {
						capabilityWant(t, ctx, tx, capabilityQuestion(t, "account", "acc-1", role), relverdict.Deny)
					} else {
						capabilityWant(t, ctx, tx, capabilityQuestion(t, "cluster", "cluster_root", role), relverdict.Deny)
					}
				}
			})
		})
	}
}

func TestGrantCapabilityNativeSourceLifecycle(t *testing.T) {
	mutations := map[string]string{
		"revoked":            `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=now() WHERE id='acb-cap-one'`,
		"expired":            `UPDATE kaname.access_bindings SET expires_at='2030-01-01' WHERE id='acb-cap-one'`,
		"pending":            `UPDATE kaname.access_bindings SET status='PENDING' WHERE id='acb-cap-one'`,
		"legacy_version":     `UPDATE kaname.access_bindings SET grant_capability_version=0 WHERE id='acb-cap-one'`,
		"finite_target":      `UPDATE kaname.access_bindings SET target='{"resources":[{"type":"iam.role","id":"rol-cap-target"}]}' WHERE id='acb-cap-one'`,
		"owner_dead":         `UPDATE kaname.roles SET live=false,retired_at=now() WHERE id='rol-cap-owner'`,
		"carrier_deleted":    `DELETE FROM kaname.access_bindings WHERE id='acb-cap-one'`,
		"projection_removed": `DELETE FROM kaname.role_create_binding_rule WHERE role_id='rol-cap-owner'`,
		"wrong_owner":        `UPDATE kaname.access_bindings SET role_id='rol-cap-other' WHERE id='acb-cap-one'`,
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			withTx(t, func(ctx context.Context, tx pgx.Tx) {
				capabilityFixture(t, ctx, tx)
				q := capabilityQuestion(t, "project", "prj-1", "")
				capabilityWant(t, ctx, tx, q, relverdict.Allow)
				exec(t, ctx, tx, mutation)
				capabilityWant(t, ctx, tx, q, relverdict.Deny)
			})
		})
	}
	for _, mutation := range []string{
		`UPDATE kaname.roles SET live=false,retired_at=now() WHERE id='rol-cap-target'`,
		`DELETE FROM kaname.roles WHERE id='rol-cap-target'`,
	} {
		withTx(t, func(ctx context.Context, tx pgx.Tx) {
			capabilityFixture(t, ctx, tx)
			q := capabilityQuestion(t, "project", "prj-1", "rol-cap-target")
			capabilityWant(t, ctx, tx, q, relverdict.Allow)
			exec(t, ctx, tx, mutation)
			capabilityWant(t, ctx, tx, q, relverdict.Deny)
			capabilityWant(t, ctx, tx, capabilityQuestion(t, "project", "prj-1", ""), relverdict.Allow)
		})
	}
}

func TestGrantCapabilityNativeIndependentSourcesAndDecisionInstant(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		capabilityFixture(t, ctx, tx)
		capabilityCarrier(t, ctx, tx, "acb-cap-two", "group", "grp-cap")
		q := capabilityQuestion(t, "project", "prj-1", "")
		exec(t, ctx, tx, `UPDATE kaname.access_bindings SET expires_at='2029-12-31' WHERE id='acb-cap-one'`)
		capabilityWant(t, ctx, tx, q, relverdict.Allow)
		exec(t, ctx, tx, `UPDATE kaname.access_bindings SET expires_at='2030-01-02' WHERE id='acb-cap-two'`)
		capabilityWant(t, ctx, tx, q, relverdict.Allow)
		q.DecisionAt = q.DecisionAt.Add(24 * time.Hour)
		capabilityWant(t, ctx, tx, q, relverdict.Deny)
		q.DecisionAt = q.DecisionAt.Add(-24 * time.Hour)
		capabilityWant(t, ctx, tx, q, relverdict.Allow)
		exec(t, ctx, tx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=now() WHERE id='acb-cap-two'`)
		capabilityWant(t, ctx, tx, q, relverdict.Deny)
	})
}

func TestGrantCapabilityNativeFailuresRemainUnknown(t *testing.T) {
	base := capabilityQuestion(t, "project", "prj-1", "")
	modelMissing, err := authzmodel.New("model\n  schema 1.1\ntype user\n")
	if err != nil {
		t.Fatal(err)
	}
	badModel, err := authzmodel.New(strings.Replace(authzmodel.DSL, "define create_binding: [user, service_account, group#member]", "define create_binding: [user]", 1))
	if err != nil {
		t.Fatal(err)
	}
	cases := []relverdict.Query{base, base, base, base, base}
	cases[0].ObjectID = "bad"
	cases[1].Relation = "bind"
	cases[2].DecisionAt = time.Time{}
	cases[3].PreparedPlans = modelMissing
	cases[4].PreparedPlans = badModel
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		capabilityFixture(t, ctx, tx)
		capabilityWant(t, ctx, tx, base, relverdict.Allow)
		for i, q := range cases {
			got, _, err := relverdict.Ask(ctx, tx, q)
			if err == nil || got != relverdict.Unknown {
				t.Fatalf("invalid case %d became answer %v: %v", i, got, err)
			}
		}
	})
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		capabilityFixture(t, ctx, tx)
		capabilityWant(t, ctx, tx, base, relverdict.Allow)
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		got, _, err := relverdict.Ask(ctx, tx, base)
		if got != relverdict.Unknown || err == nil {
			t.Fatalf("backend failure became deny: %v %v", got, err)
		}
	})
}

func TestGrantCapabilityNativeTransactionAskerPreservesAdmission(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		capabilityFixture(t, ctx, tx)
		plans, err := authzmodel.New(authzmodel.DSL)
		if err != nil {
			t.Fatal(err)
		}
		q := capabilityQuestion(t, "project", "prj-1", "")
		form := relverdict.NewTransactionAsker(tx, plans, q.DecisionAt)
		door := authzcascade.WrapAdmitted(form, personmarks.NewTransaction(tx))
		exec(t, ctx, tx, `UPDATE kaname.users SET email_verified_at=now() WHERE id='usr-1'`)
		allowed, err := door.Check(ctx, q.Subject, q.Relation, q.ObjectType+":"+q.ObjectID)
		if err != nil || !allowed {
			t.Fatalf("admitted native capability: %v %v", allowed, err)
		}
		exec(t, ctx, tx, `UPDATE kaname.users SET email_verified_at=NULL WHERE id='usr-1'`)
		allowed, err = door.Check(ctx, q.Subject, q.Relation, q.ObjectType+":"+q.ObjectID)
		if err != nil || allowed {
			t.Fatalf("missing mark did not deny: %v %v", allowed, err)
		}
		// Прежний конструктор не получает неявного времени для внутреннего решения.
		allowed, err = relverdict.NewTransactionAsker(tx, plans).Allowed(ctx, q.Subject, q.ObjectType, q.ObjectID, q.Relation, nil)
		if err == nil || allowed {
			t.Fatalf("missing explicit instant accepted: %v %v", allowed, err)
		}
	})
}

func TestGrantCapabilityNativeDoesNotTrustMaterializedFacts(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		capabilityFixture(t, ctx, tx)
		q := capabilityQuestion(t, "project", "prj-1", "")
		capabilityWant(t, ctx, tx, q, relverdict.Allow)
		exec(t, ctx, tx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES ($1,$2,$3,$4)`, q.ObjectType, q.ObjectID, q.Relation, q.Subject)
		exec(t, ctx, tx, `UPDATE kaname.access_bindings SET grant_capability_version=0 WHERE id='acb-cap-one'`)
		capabilityWant(t, ctx, tx, q, relverdict.Deny)
	})
}
