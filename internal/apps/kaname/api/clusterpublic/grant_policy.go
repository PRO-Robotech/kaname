// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clusterpublic

import (
	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations переносит декларации общего обработчика на четыре
// публичных RPC. Каждый метод Handler передаёт запрос соответствующему
// методу cluster.Handler, поэтому эффект и обязательная проверка совпадают;
// отдельного публичного пути записи или дополнительной гарантии времени
// проверки здесь нет.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	var out []grantpolicy.CatalogDeclaration
	for _, declaration := range clusterapp.GrantDeclarations() {
		switch declaration.FullMethod {
		case iamv1.InternalClusterService_Get_FullMethodName:
			declaration.FullMethod = iamv1.ClusterService_Get_FullMethodName
		case iamv1.InternalClusterService_ListAdmins_FullMethodName:
			declaration.FullMethod = iamv1.ClusterService_ListAdmins_FullMethodName
		case iamv1.InternalClusterService_GrantAdmin_FullMethodName:
			declaration.FullMethod = iamv1.ClusterService_GrantAdmin_FullMethodName
		case iamv1.InternalClusterService_RevokeAdmin_FullMethodName:
			declaration.FullMethod = iamv1.ClusterService_RevokeAdmin_FullMethodName
		default:
			continue
		}
		out = append(out, declaration)
	}
	return out
}
