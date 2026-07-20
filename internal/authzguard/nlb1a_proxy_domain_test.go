// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// nlb1a_proxy_domain_test.go — regression-lock for sub-phase NLB-1a at the FGA-proxy
// least-privilege guard. After the hard-rename kacho-nlb owns `nlb_*`-prefixed FGA
// object types (matching its mTLS SAN short-name "nlb"), so the domain-binding must
// (a) ADMIT owner-hierarchy tuples on the renamed `nlb_*` objects and (b) REJECT the
// legacy `lb_*` objects — proving no dangling old-type write-path survives the rename.
//
// This is the fgaproxy half of NLB-1a-04 (no-binding / cross-domain deny) and
// NLB-1a-05 (old lb_* no longer resolves). Traceability: NLB-1a-04/05.
func TestNLB1a_ProxyDomainBinding_NlbOwnsNlbPrefix(t *testing.T) {
	cases := []struct {
		name     string
		caller   string
		subject  string
		relation string
		object   string
		want     codes.Code // codes.OK → nil
	}{
		// (a) nlb may register owner-hierarchy tuples on its renamed nlb_* objects.
		{"nlb registers listener (nlb_listener)", "nlb", "project:prj1", "project", "nlb_listener:lsn1", codes.OK},
		{"nlb registers LB (nlb_network_load_balancer)", "nlb", "project:prj1", "project", "nlb_network_load_balancer:nlb1", codes.OK},
		{"nlb creator owner on LB", "nlb", "user:usr1", "owner", "nlb_network_load_balancer:nlb1", codes.OK},
		{"nlb registers target group (nlb_target_group)", "nlb", "project:prj1", "project", "nlb_target_group:tgr1", codes.OK},
		// (b) the LEGACY lb_* objects are no longer nlb's domain → fail-closed deny
		//     (NLB-1a-05: rename left no dangling old-type write-path).
		{"nlb DENIED on legacy lb_network_load_balancer", "nlb", "user:usr1", "owner", "lb_network_load_balancer:nlb1", codes.PermissionDenied},
		{"nlb DENIED on legacy lb_listener", "nlb", "project:prj1", "project", "lb_listener:lsn1", codes.PermissionDenied},
		{"nlb DENIED on legacy lb_target_group", "nlb", "project:prj1", "project", "lb_target_group:tgr1", codes.PermissionDenied},
		// (b') cross-domain deny is unaffected: nlb may not write a vpc object.
		{"nlb DENIED on foreign vpc object", "nlb", "user:usr1", "owner", "vpc_network:net1", codes.PermissionDenied},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyTuple(tt.caller, tt.subject, tt.relation, tt.object)
			got := status.Code(err)
			if tt.want == codes.OK {
				if err != nil {
					t.Fatalf("ValidateProxyTuple(%q,%q,%q,%q) = %v; want nil (nlb owns nlb_* after NLB-1a)",
						tt.caller, tt.subject, tt.relation, tt.object, err)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("ValidateProxyTuple(%q,%q,%q,%q) code = %v; want %v",
					tt.caller, tt.subject, tt.relation, tt.object, got, tt.want)
			}
		})
	}
}
