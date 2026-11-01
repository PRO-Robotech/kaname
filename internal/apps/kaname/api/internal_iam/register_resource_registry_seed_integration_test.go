//go:build integration

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Проба читает настоящее намерение посева: собственная копия цепи предков
// скрыла бы расхождение производителя с контрактом регистрации (kaname#1096).
func TestRegisterResource_RegistrySeedIntentMatchesParentHierarchy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	uc, pool := newRegisterUCApplied(t)
	scene := registrationscene.Seed(t, ctx, pool)
	values, err := json.Marshal(map[string]string{"accountAId": scene.Account, "projectA1Id": scene.Project})
	require.NoError(t, err)
	command := exec.CommandContext(ctx, "python3", "-c", `import json, sys
sys.path.insert(0, 'tests/authz-fixtures')
import seed_registry_resource as seed
print(json.dumps(seed.intent(json.loads(sys.argv[1]))))`, string(values))
	command.Dir = "../../../../.."
	body, err := command.CombinedOutput()
	require.NoError(t, err, "производитель намерения не исполнился: %s", body)
	request := new(iamv1.RegisterResourceRequest)
	require.NoError(t, protojson.Unmarshal(body, request))

	// Законный близнец отличается только цепью; тот же объект, версия и проект.
	twin := proto.Clone(request).(*iamv1.RegisterResourceRequest)
	twin.ParentChain = scene.ProjectChain()
	require.NoError(t, uc.Register(ctx, twin), "условие регистрации исправного близнеца")

	// Лишнее звено по-прежнему отвергается службой, в том числе при повторе.
	foreign := proto.Clone(twin).(*iamv1.RegisterResourceRequest)
	foreign.ParentChain = append(foreign.ParentChain, "cluster:cluster_root")
	err = uc.Register(ctx, foreign)
	require.ErrorIs(t, err, iamerr.ErrParentScopeMismatch)
	require.Equal(t, "failed precondition: "+foreign.Object+" parent scope does not match", err.Error())

	require.NoError(t, uc.Register(ctx, request), "настоящее намерение registry должно приниматься")
	require.NoError(t, uc.Register(ctx, request), "повтор настоящего намерения должен приниматься")
	require.Equal(t, 1, mirrorRowCount(t, ctx, pool, "registry.registries", request.Object[len("registry_registry:"):]))
}
