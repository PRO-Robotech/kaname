// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestNTF1M10b_RegisterResourceRefusesTheNotificationTypes — тенантская
// поверхность прокси-записи (`RegisterResource` и соседи по правилу) кортежа на
// объекте типов `service`, `notification_feed`, `notification_namespace` не
// пишет: `PERMISSION_DENIED`, текст `permission denied` (приёмка NTF-1,
// NTF1-M10 (б)). Запрет держит запись типов в `forbiddenObjectTypes`
// фундамента; здесь замкнуто то, что наблюдает вызывающий на этой границе.
//
// Близнец — тот же вызов на разрешённом типе своего домена: принят. Без него
// проба зеленела бы на границе, отвергающей всё.
func TestNTF1M10b_RegisterResourceRefusesTheNotificationTypes(t *testing.T) {
	t.Parallel()
	for _, object := range []string{"service:probe", "notification_feed:probe", "notification_namespace:probe"} {
		err := validateProxyTuple("probe", "project:prj1", "project", object)
		if got := status.Code(err); got != codes.PermissionDenied {
			t.Fatalf("%s: код %v, ожидался %v", object, got, codes.PermissionDenied)
		}
		if got := status.Convert(err).Message(); got != "permission denied" {
			t.Fatalf("%s: текст %q, ожидался %q", object, got, "permission denied")
		}
	}
	if err := validateProxyTuple("vpc", "project:prj1", "project", "vpc_network:net1"); err != nil {
		t.Fatalf("законный кортеж своего домена отвергнут — граница отвергает всё: %v", err)
	}
}
