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

An object advisory transaction fence closes the missing-row case. Commands with
an existing locked mirror take its fence and lock the existing edge rows before
comparing the chain in a separate SQL statement. Commands whose initial mirror
lookup was empty first perform the effective mirror CAS, then take the fence and
edge locks. This preserves mirror-before-fence order even if a concurrent raw
UPSERT inserted the mirror between those statements. A raw mirror writer takes
the fence only in its AFTER effective-row guard; a raw UPSERT waiting on a mirror
cannot already own the fence or binding. First raw binding creation also checks
the existing chain; a failure rolls the whole statement back.

A raw project-edge INSERT takes the destination object's fence before its row
exists. A raw UPDATE that changes the object key does the same: its old locked
row belongs to another object's chain. A raw UPDATE of the SAME object key must
not take that fence after its row lock. Its committed old row is visible to the
command's edge-lock statement, which waits before reading the fresh chain. If
the command got the edge lock first, the raw UPDATE waits and its row guard then
sees the committed binding. This distinction avoids the edge-to-fence inversion.
Raw edge statement triggers take compatible catalog SHARE locks before any edge
row locks, so a pending catalog declaration cannot introduce a catalog/edge lock
cycle. Nested command DML already holds the relevant catalog lock and omits this
statement guard under the same closed-graph proof.

The additional ordinary-command cost for a held type is one advisory lock and
one ordered lock scan over its at-most-four existing edge rows, with no extra
binding lookup. Commands on independent object keys remain concurrent; raw
statements briefly share-lock the catalog, and do not serialize each other.
Hash collisions can introduce additional waiting, never an integrity exemption.
There are no deferred constraints, lock-mode upgrades, new stored permits or
client-controlled switches. SET CONSTRAINTS IMMEDIATE does not alter the
protocol. As with ordinary multi-object SQL transactions, callers must keep a
consistent object order; no promise of deadlock-free arbitrary SQL ordering is
made. The scoped tests retain the original manual-mirror-lock/raw-UPSERT twin,
the original raw INSERT probe, and same-key/key-moving UPDATE twins. Latency and
buffer measurements remain a separate acceptance gate.

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
