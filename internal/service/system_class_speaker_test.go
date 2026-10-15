// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// system_class_speaker_test.go — разборщик говорящего ОДИН на все методы,
// принимающие субъекта (приёмка anonymous-and-authenticated-are-subject-classes.md,
// отпечаток ae9ba373…0427f51, SC-14, SC-10; kaname#829; разбор CE-04).
//
// Отказ «вошедший без личности не говорит» в одном `Check` оставил бы
// `CheckRelation` (внутреннюю дверь каждой службы) и `BatchCheck` спрашивающими
// от его имени. Проба судит текст отказа на каждом из трёх, а близнец —
// аноним — проходит разбор на каждом.

import (
	"context"
	"testing"
)

const scRefusal = "Illegal argument subject: system class authenticated is not a speaker"

func TestSystemClass_SC14_EverySubjectDoorRefusesTheAuthenticatedSpeaker(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: &mockRelations{checkResp: false}})
	ctx := context.Background()
	req := func(subject string) CheckRequest {
		return CheckRequest{Subject: subject, Resource: ResourceRef{Type: "vpc_network", ID: "enp00000000000000001"},
			Action: "vpc.networks.get"}
	}

	if _, err := svc.Check(ctx, req("system_class:authenticated")); err == nil || err.Error() != scRefusal {
		t.Errorf("Check: отказ %v, ждали %q", err, scRefusal)
	}
	if _, err := svc.CheckRelation(ctx, CheckRelationRequest{
		Subject: "system_class:authenticated", Relation: "v_get", Object: "vpc_network:enp00000000000000001",
	}); err == nil || err.Error() != scRefusal {
		t.Errorf("CheckRelation: отказ %v, ждали %q", err, scRefusal)
	}
	out, err := svc.BatchCheck(ctx, []CheckRequest{req("system_class:authenticated"), req("system_class:anonymous")})
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	if len(out[0].DenyReasons) != 1 || out[0].DenyReasons[0] != scRefusal || out[0].Allowed {
		t.Errorf("BatchCheck: пункт «вошедшего» = %+v, ждали отказ %q", out[0], scRefusal)
	}

	// Близнец: аноним — говорящий; ответ по выдачам (здесь их нет), не отказ
	// разбора, и «пути нет» выражено отсутствием причин (SC-10).
	res, err := svc.Check(ctx, req("system_class:anonymous"))
	if err != nil {
		t.Fatalf("Check анонима: %v", err)
	}
	if res.Allowed || len(res.DenyReasons) != 0 {
		t.Errorf("Check анонима = %+v, ждали allowed=false без причин", res)
	}
	if len(out[1].DenyReasons) != 0 || out[1].Allowed {
		t.Errorf("BatchCheck анонима = %+v, ждали allowed=false без причин", out[1])
	}
	rel, err := svc.CheckRelation(ctx, CheckRelationRequest{
		Subject: "system_class:anonymous", Relation: "v_get", Object: "vpc_network:enp00000000000000001",
	})
	if err != nil {
		t.Fatalf("CheckRelation анонима: %v", err)
	}
	if rel.Allowed || len(rel.DenyReasons) != 0 {
		t.Errorf("CheckRelation анонима = %+v, ждали allowed=false без причин", rel)
	}

	// Контроль: человеку причина отказа называется, как прежде.
	usr, err := svc.Check(ctx, req("user:usr-sc14"))
	if err != nil {
		t.Fatalf("Check человека: %v", err)
	}
	if usr.Allowed || len(usr.DenyReasons) == 0 {
		t.Errorf("Check человека = %+v, ждали отказ с причиной", usr)
	}
}
