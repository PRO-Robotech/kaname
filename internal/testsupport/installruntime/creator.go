// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// StandingCreator records the three normal successful Operations which create
// C, grant its authority, and issue its durable key. No database writer enters
// this helper. The fullserve fixture separately checks all persisted identities.
type StandingCreator struct {
	ID, AccountID, ClientID, KeyID, CredentialFile string
	CreateOperation, GrantOperation, KeyOperation  Operation
	privateKey                                     string
	ExpiresAt                                      time.Time
}

func (c *StandingCreator) SecretMaterial() []string { return []string{c.privateKey} }

func (w *Wire) createOperation(ctx context.Context, operator *VerifiedOperator, path string, body any) (Operation, error) {
	var op Operation
	code, err := w.JSON(ctx, http.MethodPost, path, operator.Bearer(), body, &op)
	if err != nil {
		return op, err
	}
	if code != http.StatusOK {
		return op, fmt.Errorf("ordinary creation API returned HTTP %d", code)
	}
	return w.AwaitOperation(ctx, operator.Bearer(), op)
}

// ProvisionStandingCreator requires O's real ceremony bearer. GrantAdmin goes
// through the real mTLS gateway-fronted listener with only verified O metadata;
// that listener must independently enforce current authority and ACR.
func (w *Wire) ProvisionStandingCreator(ctx context.Context, operator *VerifiedOperator, systemAccountID, credentialFile string) (*StandingCreator, error) {
	return w.ProvisionStandingCreatorWithKeyTTL(ctx, operator, systemAccountID, credentialFile, 7200)
}

// ProvisionStandingCreatorWithKeyTTL selects a declared ordinary Issue lifetime.
// Validation and expiry remain the production key API and real wall clock.
func (w *Wire) ProvisionStandingCreatorWithKeyTTL(ctx context.Context, operator *VerifiedOperator, systemAccountID, credentialFile string, ttlSeconds int64) (*StandingCreator, error) {
	if ttlSeconds <= 0 {
		return nil, errors.New("positive declared standing-key lifetime required")
	}
	if operator == nil || operator.userID == "" || systemAccountID == "" || !filepath.IsAbs(credentialFile) {
		return nil, errors.New("verified O, canonical system account and private absolute credential path are required")
	}
	create, err := w.createOperation(ctx, operator, "/iam/v1/serviceAccounts", map[string]any{
		"accountId": systemAccountID, "name": "rid-native-standing-creator", "description": "Generic installation acceptance creator"})
	if err != nil {
		return nil, err
	}
	var sa struct {
		ID        string `json:"id"`
		AccountID string `json:"accountId"`
	}
	if json.Unmarshal(create.Response, &sa) != nil || sa.ID == "" || sa.AccountID != systemAccountID {
		return nil, errors.New("normal SA Create response changed canonical account or omitted identity")
	}
	conn, err := w.Gateway("localhost:9091")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	granted, err := iamv1.NewInternalClusterServiceClient(conn).GrantAdmin(operator.GatewayContext(ctx), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, SubjectId: sa.ID})
	if err != nil {
		return nil, fmt.Errorf("normal gateway GrantAdmin failed: %w", err)
	}
	raw, err := protojson.Marshal(granted)
	if err != nil {
		return nil, errors.New("gateway Operation is not serializable")
	}
	var grant Operation
	if json.Unmarshal(raw, &grant) != nil {
		return nil, errors.New("gateway Operation shape is invalid")
	}
	grant, err = w.AwaitOperation(ctx, operator.Bearer(), grant)
	if err != nil {
		return nil, err
	}
	issued, err := w.createOperation(ctx, operator, "/iam/v1/serviceAccounts/"+sa.ID+"/keys", map[string]any{
		"credentialKind": "CREDENTIAL_KIND_KEYPAIR", "description": "RID durable standing creator", "ttlSeconds": ttlSeconds})
	if err != nil {
		return nil, err
	}
	var key struct {
		ClientID      string `json:"clientId"`
		KeyID         string `json:"keyId"`
		PrivateKeyPEM string `json:"privateKeyPem"`
		Algorithm     string `json:"algorithm"`
	}
	if json.Unmarshal(issued.Response, &key) != nil || key.ClientID == "" || key.KeyID == "" || key.PrivateKeyPEM == "" || key.Algorithm != "ES256" {
		return nil, errors.New("normal key Issue did not return a complete ES256 standing key")
	}
	material, err := json.Marshal(map[string]string{"clientId": key.ClientID, "keyId": key.KeyID, "privateKeyPem": key.PrivateKeyPEM})
	if err != nil {
		return nil, errors.New("standing credential cannot be serialized")
	}
	file, err := os.OpenFile(credentialFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(material)
	closeErr := file.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return &StandingCreator{ID: sa.ID, AccountID: sa.AccountID, ClientID: key.ClientID, KeyID: key.KeyID,
		CredentialFile: credentialFile, CreateOperation: create, GrantOperation: grant, KeyOperation: issued, privateKey: key.PrivateKeyPEM}, nil
}
