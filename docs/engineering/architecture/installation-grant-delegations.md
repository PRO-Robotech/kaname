# Installation grant delegations

The existing `kaname serve` startup reads `seed.grantDelegations` from delivered
module manifests. The accepted contract is
[Registry installation delegation](../acceptance/registry-installation-seeds-its-grant-delegation.md).
This note describes the implementation inputs and dependency seams; runtime and
public-edge acceptance evidence are separate from source implementation.

The installation configuration uses the accepted public input:

```yaml
moduleSeedInstaller:
  credentialFile: /run/secrets/module-seed-installer.json
  tenantAccountId: <existing account ID>
```

Declaring `tenantAccountId` selects a single tenant. Omit it for the complete
canonical tenant census; an explicitly empty value is refused. Page size is an
internal implementation detail. The system account is never a tenant target.

The credential file is a private regular JSON file, at most 65536 bytes, with
exactly the declared fields `clientId`, `keyId`, and `privateKeyPem`. They come
from the one-time response of the existing SAKey KEYPAIR issuance for the durable
installer C. File permissions must exclude group and other access. The file
contains standing secret material and must be mounted as a protected secret.
The configuration supplies credentials; it never supplies a principal.

An independent administrator O provisions C and grants it actual typed
`service_account:C` system-admin authority through the existing administrative
APIs. Startup authenticates the same standing key, reuses its issued access token within
its lifetime, and verifies that token normally on every pair. It
uses the shared client-assertion verifier and token issuer, followed by normal
presented-credential verification. Assertion audience is the installation issuer;
the requested access-token audience is the configured presented-credential
audience. Issuance, replay, revocation and deadline policy remain in their existing
production components. Access-token expiration does not provision another C,
key, or grant.

The startup sequence is whole-delivery loading and linkage, pure model
composition/admission, input and credential validation, verified current authority,
model installation, existing catalog/role/ordinary seed writers, and delegation
application. Listener readiness follows the last stage. Prepared model plans
allow the real relational authority query before process model installation,
without reading or resetting the global model. Authentication bookkeeping is
separate from delivery writes.

The complete tenant census uses the primary database, canonical seed identity
resolver, and ID pagination over one PostgreSQL read-only repeatable-read transaction.
Each page opens a nested scope on that transaction through `InstallationPageFactory.BeginTx`.
Accounts committed after snapshot fixation enter the next apply. The same
factory is a production dependency that can be decorated for telemetry, deadlines
or fault injection; a late reader failure cannot turn an incomplete census into
an empty successful result.

Each pair uses `CreateGrantDelegationUseCase.ExecuteInstallation`, retaining
ordinary validation, current authority, durable Operations and audit writes.
Create, installation history checks and Revoke serialize on the same transaction
pair lock. Exact ACTIVE creator/axes matches retain their resource identity;
conflicting ACTIVE state and REVOKED-only history refuse installation without
replacement. Ordinary explicit Create retains its existing replacement policy.

The normal Operation is created with a fresh proposed GD ID before opening the
writer transaction. The writer locks that pending Operation row before the pair
lock, then checks actual current authority using the admitted production verdict
and person marks on the same transaction. The winning GD ID, split Any metadata
and Operation resource index commit together; the ordinary worker still writes
the terminal outcome. GD recovery reads the primary. No additional pool slot is
needed for the in-lock guard, including at pool width one.

The implementation test helper `newInstallationBootstrapWorld` provides an
initial isolated O from the existing ceremony fixture and `RunBootstrapAdmin`.
Its O token passes the real presented-credential reader; it does not seed C/I/GD.
`TestInstallationPreparedAuthorityBeforeFirstInstall` runs in a fresh helper
process to test the first-install boundary. The independent acceptance fixture
must additionally exercise permitted gateway transport and real production
listeners for the complete twelve RID scenarios.
