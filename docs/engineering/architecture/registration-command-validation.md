# Complete registration validation (kaname#983)

The stateless `kaname.resource_registration_command` view accepts the complete
mirror payload and ordered chain. Its sole INSTEAD OF INSERT trigger owns every
physical write. `type_live`, `model_type`, `applied`, `projection_unchanged` are
always overwritten with DB outcomes. There is no callable partial writer, new
role, SECURITY DEFINER, DSN, permit row, client flag or GUC.

The effective protocol is mirror lock → fresh catalog/chain snapshot → provisional
mirror CAS → binding INSERT if applied → one binding PK SELECT → full field/chain
validation → edge projection. Separate VOLATILE SPI statements preserve the
kaname#874 fresh snapshot after lock waiting. When the initial lock found no row,
the version-only optimization is disabled: an insertion race gets the conservative
projection-changed outcome. Strict `<` and unknown/retired type refusal remain.

Provisional mirror DML is deliberately before binding creation. An error rolls
back the entire command statement, including that DML and its binding. No audit,
notification, arbitrary callback or nontransactional effect may run on provisional
mirror writes. A stale/no-op command still validates its entire payload against
one binding read; it cannot create a first binding. Raw BEFORE mirror guards judge
existing binding, while raw AFTER effective-row guards create and recheck binding.
Thus a raw INSERT ON CONFLICT cannot hold a binding insert lock while waiting for
the mirror row held by the command: all effective writers use mirror → binding.
Catalog declarations remain serialized by SHARE versus UPDATE catalog locks;
declaration backfill never rewrites or validates historical chains (R8).

## Raw edge concurrency

Every command and physical mirror/edge/catalog write takes the same exclusive
advisory transaction fence in a BEFORE STATEMENT trigger, before row locks.
INSERT, UPDATE, DELETE and TRUNCATE participate. Nested writes reacquire the same
transaction lock safely. Catalog writes enter before declaration row locks; the catalog applier takes
the same fence in LockCatalog before its explicit module/resource prelocks;
unregistration enters in LockBindingsNamingKeys before its complete grant/role
lock plan. The bindings -> roles -> mirror -> facts order remains (#975/#1019);
taking the fence only at DELETE would invert with catalog retirement FK checks
on roles. Commands still read the chain in a separate VOLATILE SQL
statement after waiting (#874). The one/zero binding-read contract is unchanged.

This serializes registration write transactions, including raw DML. A raw edge
insert cannot remain invisible to a command that creates the first binding: the
command waits until raw commit, then replaces the committed chain. A raw mirror
first registration also checks its existing chain. A mismatch fails atomically
with object_project_binding_holds. Historical catalog backfill retains R8 chains.
There are no deferred constraints, client flags, permits or shared-to-exclusive
lock upgrades. SET CONSTRAINTS IMMEDIATE does not alter this protocol. Commands
and raw statements can be mixed in either order in one transaction.

The raw-UPSERT barrier test now holds the writer transaction with a genuine stale
command rather than a manual SELECT FOR NO KEY UPDATE before command entry. Its
semantic assertions remain: both lawful writers commit, no deadlock, correct
permanent binding. Arbitrary row locks taken outside the writer protocol can
still create ordinary SQL lock-order cycles; no absence-of-deadlock guarantee for
such prelocks is inferred from R9. The original manual-prelock schedule is not
claimed fixed. The actual UpsertTx has one command statement and no such prelock.

The cost is one transaction-wide exclusive fence, not merely the binding SELECT
count. The acceptance latency/EXPLAIN measurement and concurrent-writer controls
must assess this serialization before approval. Independent objects no longer
write in parallel; this is an explicit implementation tradeoff, not an accepted
performance result. No performance threshold or accepted criterion is changed.

## Closed trigger graph is the authority

Only direct depth-one command entry is accepted. Physical mirror/edge guards omit
redundant work only at exactly depth two. This is sound because the complete
command is the ONLY trigger-reachable writer of these physical tables. Depth
alone is not authority: introducing another writer invalidates the proof.

The command contains static DML and built-in operations over text/jsonb/timestamp
inputs. It cannot call client-selected functions or SQL. The mirror/edge guards
write only binding; binding UPDATE/DELETE/TRUNCATE permanence is never bypassed.
Catalog declaration triggers write binding, not mirror/edges. Journal, quota,
subject and reconcile triggers do not reach a physical mirror/edge writer.
`rename_cluster_anchor(text,text)` is an existing dynamic writer: ordinary SELECT
entry has no trigger depth, so its physical writes receive full depth-one guards.
It must never become reachable from another trigger. It receives no exemption.

`TestPermanentProjectCommand_InstalledTriggerGraphIsClosed` inventories installed
user triggers and follows named custom function calls conservatively. It rejects
other static physical writers, unreviewed dynamic SQL, trigger-reachable rename,
physical rewrite/FK/RLS callbacks and new mirror/edge side-effect triggers. It is
a finite change detector supporting schema review, not a SQL parser or permission
to ignore callbacks hidden in novel SQL syntax. New functions, policies, checks,
indexes, rewrite rules or trigger paths must be reviewed for closure before this
optimization remains valid. Arbitrary administrator DDL is outside the accepted
ordinary-DML threat model, just as for the original immutable-binding triggers.

## Collision of historical version 20261026090000

Main's creator migration remains unchanged. Exact feature bytes are retained in
`internal/migrations/historical/20261026090000_module_writes_only_what_its_manifest_declares.sql`,
outside executable `migrations.FS`; its checksum is recorded in reconciliation
90001. No goose ledger row is rewritten or reinterpreted as proof of one lineage.

90001 recognizes complete column/default/constraint definitions, creator
function/trigger/index and the corresponding rule validator. Recognition precedes
persistent mutation. It applies the original Up body only for an entirely absent
side; existing catalog data is not reseeded. Fresh/main-only/feature-only/both
converge; unexpected partial or changed definitions fail closed. Product
`migratorrun.Runner.Up` already uses `goose.WithAllowMissing`, so a feature database
already at 120000 receives missing 90001. The upgrade matrix uses this actual
runner, with complete original lineages, repeat upgrade and data preservation.
Automatic Down of reconciliation refuses: the ambiguous historical ledger does
not reveal which side can safely be removed.

## Evidence boundary

Required external controls include full Upsert and Register nested-query counts
(with a two-read observer control), multi-project-link chains, raw DML and spoofed
command inputs, atomic rollback, stale/no-op no-first-binding, and the legal raw
UPSERT/command mirror-lock barrier. Existing R8/R8a, first-binding races, source
version/chain movement, four mirror writers, scalegrid parity and error precedence
remain required. The kaname#1019 whole-transaction closure retry is independent;
it must pass its real PostgreSQL deadlock reproducer and kaname#975 regressions.
A code commit or an isolated EXPLAIN is not evidence of these runtime properties.
