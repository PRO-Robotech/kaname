// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestValidateProxyTuple проверяет least-privilege guard FGA-proxy write-path:
// модульная SA может писать только owner-hierarchy tuple в объект СВОЕГО домена,
// и никогда — privilege relation или платформенный/cluster объект.
func TestValidateProxyTuple(t *testing.T) {
	tests := []struct {
		name         string
		callerDomain string
		subject      string
		relation     string
		object       string
		wantCode     codes.Code // codes.OK → ожидаем nil
	}{
		// Привилегия-эскалация: vpc-SA пытается выписать cluster-admin.
		{"vpc mints cluster system_admin", "vpc", "service_account:sva1", "system_admin", "cluster:cluster_kacho_root", codes.PermissionDenied},
		{"vpc mints cluster admin", "vpc", "service_account:sva1", "admin", "cluster:cluster_kacho_root", codes.PermissionDenied},
		// Privilege relation на своем же объекте — тоже запрещено (только hierarchy).
		{"vpc editor on own object", "vpc", "user:usr1", "editor", "vpc_network:net1", codes.PermissionDenied},
		{"vpc viewer on own object", "vpc", "user:usr1", "viewer", "vpc_network:net1", codes.PermissionDenied},
		{"vpc v_get on own object", "vpc", "user:usr1", "v_get", "vpc_network:net1", codes.PermissionDenied},
		{"vpc fga_writer on own object", "vpc", "service_account:sva1", "fga_writer", "vpc_network:net1", codes.PermissionDenied},
		// Foreign-domain object: vpc-SA пишет в iam/compute/nlb объект.
		{"vpc writes iam account object", "vpc", "user:usr1", "owner", "iam_account:acc1", codes.PermissionDenied},
		{"vpc writes account object", "vpc", "user:usr1", "owner", "account:acc1", codes.PermissionDenied},
		{"vpc writes compute object", "vpc", "user:usr1", "owner", "compute_instance:inst1", codes.PermissionDenied},
		{"vpc writes project object", "vpc", "project:prj1", "owner", "project:prj1", codes.PermissionDenied},
		// cluster object запрещен даже c hierarchy-relation и даже без известного домена (dev-mode).
		{"hierarchy relation but cluster object", "", "service_account:sva1", "project", "cluster:cluster_kacho_root", codes.PermissionDenied},
		// Легитимные owner-hierarchy tuple — проходят.
		{"vpc registers network under project", "vpc", "project:prj1", "project", "vpc_network:net1", codes.OK},
		{"compute registers instance under project", "compute", "project:prj1", "project", "compute_instance:inst1", codes.OK},
		// kacho-nlb владеет доменом loadbalancer, чьи FGA-object-типы после NLB-1a
		// префиксуются `nlb_` (nlb_network_load_balancer / nlb_listener /
		// nlb_target_group) — совпадают с SAN short-name "nlb" (domain-binding default).
		{"nlb registers listener under project", "nlb", "project:prj1", "project", "nlb_listener:lsn1", codes.OK},
		{"nlb registers load balancer under project", "nlb", "project:prj1", "project", "nlb_network_load_balancer:nlb1", codes.OK},
		{"nlb creator owner on load balancer", "nlb", "user:usr1", "owner", "nlb_network_load_balancer:nlb1", codes.OK},
		// nlb не вправе писать в чужой домен (vpc_*), даже с hierarchy-relation.
		{"nlb writes vpc object", "nlb", "user:usr1", "owner", "vpc_network:net1", codes.PermissionDenied},
		{"vpc creator owner tuple", "vpc", "user:usr1", "owner", "vpc_network:net1", codes.OK},
		// Empty inputs — InvalidArgument (грамматика проверяется отдельно, но guard fail-closed).
		{"empty relation", "vpc", "project:prj1", "", "vpc_network:net1", codes.PermissionDenied},
		{"empty object", "vpc", "project:prj1", "project", "", codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyTuple(tt.callerDomain, tt.subject, tt.relation, tt.object)
			gotCode := status.Code(err)
			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("ValidateProxyTuple(%q,%q,%q,%q) = %v; want nil",
						tt.callerDomain, tt.subject, tt.relation, tt.object, err)
				}
				return
			}
			if gotCode != tt.wantCode {
				t.Fatalf("ValidateProxyTuple(%q,%q,%q,%q) code = %v; want %v (err=%v)",
					tt.callerDomain, tt.subject, tt.relation, tt.object, gotCode, tt.wantCode, err)
			}
		})
	}
}
