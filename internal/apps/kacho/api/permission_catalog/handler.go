// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package permission_catalog

// handler.go — thin gRPC transport for PermissionCatalogService.
// Registered on the PUBLIC listener (grantable-token metadata,
// not infra-sensitive). parse → use-case → format. No business logic.

import (
	"context"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// Handler — gRPC server for PermissionCatalogService.
type Handler struct {
	iamv1.UnimplementedPermissionCatalogServiceServer

	list *ListPermissionCatalogUseCase
}

// NewHandler — builder.
func NewHandler(list *ListPermissionCatalogUseCase) *Handler {
	return &Handler{list: list}
}

// ListPermissionCatalog — sync read of the grantable role-rule taxonomy.
// AuthZ: authenticated-floor enforced in the use-case (anonymous → fail-closed,
// G-02); the catalog is platform-wide metadata (not per-tenant scoped, G-D3).
func (h *Handler) ListPermissionCatalog(ctx context.Context, _ *iamv1.ListPermissionCatalogRequest) (*iamv1.ListPermissionCatalogResponse, error) {
	cat, err := h.list.Execute(ctx)
	if err != nil {
		// Execute returns a gRPC status (RequireAuthenticated → PermissionDenied);
		// pass it through unwrapped so the code/text reach the client verbatim.
		return nil, err
	}
	return catalogToProto(cat), nil
}

// catalogToProto projects the use-case Catalog DTO onto the proto wire shape
// (camelCase on the wire via the proto field json tags).
func catalogToProto(c Catalog) *iamv1.ListPermissionCatalogResponse {
	modules := make([]*iamv1.CatalogModule, 0, len(c.Modules))
	for _, m := range c.Modules {
		resources := make([]*iamv1.CatalogResource, 0, len(m.Resources))
		for _, r := range m.Resources {
			resources = append(resources, &iamv1.CatalogResource{
				Resource:         r.Resource,
				HasVerbRelations: r.HasVerbRelations,
				HasListEndpoint:  r.HasListEndpoint,
				LabelSelectable:  r.LabelSelectable,
			})
		}
		modules = append(modules, &iamv1.CatalogModule{
			Module:    m.Module,
			Resources: resources,
		})
	}
	return &iamv1.ListPermissionCatalogResponse{
		Modules:     modules,
		ClosedVerbs: c.ClosedVerbs,
		WildcardPolicy: &iamv1.WildcardPolicy{
			VerbWildcardAllowedCustom:        c.Wildcard.VerbWildcardAllowedCustom,
			ModuleResourceWildcardSystemOnly: c.Wildcard.ModuleResourceWildcardSystemOnly,
		},
	}
}
