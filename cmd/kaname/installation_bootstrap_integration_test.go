// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// installationBootstrapWorld is an INITIAL isolated installation Given. Only O's
// pre-existing registered user/session/client come from ceremonyWorld's setup.
// Its actual ceremony token is verified by the production presented reader; the
// existing startup bootstrap producer grants O authority. C/I/GD are never seeded.
// Public/gateway assertions belong to the independent edge fixture.
type installationBootstrapWorld struct {
	world     *ceremonyWorld
	principal context.Context
	reader    *presentedcred.Reader
	model     preparedModel
	relations *authzcascade.Client
}

func newInstallationBootstrapWorld(t *testing.T, opts ...worldOption) *installationBootstrapWorld {
	t.Helper()
	w := newCeremonyWorld(t, "INSTALLATION-F0", "2", opts...)
	w.markPerson()
	token := w.redeem(w.issueCode(w.ic1, lineA1R))
	reader, err := presentedcred.New(presentedcred.Config{
		Issuer: lineA1Issuer, Audience: "https://api.kacho.local", AllowedAlgorithms: []string{"ES256"},
		Keys: ceremonyPublished{w: w}, Revocations: kanamepg.NewMintedTokenRevocationRepo(w.pool),
		RevocationCacheTTL: time.Millisecond, Logger: quietLogger(),
	})
	require.NoError(t, err)
	var principal context.Context
	incoming := metadata.NewIncomingContext(w.ctx, metadata.Pairs(presentedcred.MetadataKey, "Bearer "+token.AccessToken))
	_, err = reader.UnaryOver(nil)(incoming, nil, &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AccountService/Get"}, func(ctx context.Context, _ any) (any, error) { principal = ctx; return nil, nil })
	require.NoError(t, err, "Given O must authenticate by the ordinary production reader")
	p, ok := operations.PrincipalFromContextOK(principal)
	require.True(t, ok)
	require.Equal(t, "user", p.Type)
	require.Equal(t, string(w.user), p.ID)
	prepared, err := prepareComposedModel(quietLogger(), nil)
	require.NoError(t, err)
	relations := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(w.pool, prepared.plans), personmarks.New(w.pool))
	allowed, err := authzguard.IsClusterAdminE(principal, relations)
	require.NoError(t, err)
	require.False(t, allowed, "ordinary registered O has no admin authority before bootstrap")
	writer, err := kanamepg.New(w.pool, nil).Writer(principal)
	require.NoError(t, err)
	capability, ok := writer.(installationTransactionControl)
	require.True(t, ok)
	require.Equal(t, codes.PermissionDenied, status.Code(capability.RequireInstallationAuthority(principal, prepared.plans)), "unprivileged authenticated O must be denied, not an unanswered backend question")
	require.NoError(t, writer.Rollback(principal))
	result, err := seed.RunBootstrapAdmin(w.ctx, w.pool, quietLogger(), seed.BootstrapAdminInput{Email: w.email})
	require.NoError(t, err)
	require.False(t, result.Skipped)
	require.Equal(t, string(w.user), result.UserID)
	allowed, err = authzguard.IsClusterAdminE(principal, relations)
	require.NoError(t, err)
	require.True(t, allowed, "actual bootstrap journal must materialize O system_admin")
	return &installationBootstrapWorld{world: w, principal: principal, reader: reader, model: prepared, relations: relations}
}

// The helper process is essential: an already installed model in another test
// cannot prove that authenticated current-authority preflight leaves FIRST Install
// possible. No model reset or global mutation is used.
func TestInstallationPreparedAuthorityBeforeFirstInstall(t *testing.T) {
	const marker = "KANAME_TEST_INSTALLATION_PREPARED_AUTHORITY_CHILD"
	if os.Getenv(marker) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInstallationPreparedAuthorityBeforeFirstInstall$", "-test.v")
		cmd.Env = append(os.Environ(), marker+"=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "fresh helper process: %s", out)
		t.Log(string(out))
		return
	}
	fixture := newInstallationBootstrapWorld(t)
	require.NoError(t, authzmodel.Install(fixture.model.text), "verified current authority must not freeze global model before first Install")
	ordinary := authzcascade.WrapAdmitted(relverdict.NewAsker(fixture.world.pool), personmarks.New(fixture.world.pool))
	allowed, err := authzguard.IsClusterAdminE(fixture.principal, ordinary)
	require.NoError(t, err)
	require.True(t, allowed, "ordinary post-install authority must agree with prepared authority")
}
