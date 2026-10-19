# Boundary, Identity, and Grant Composition

*Written before the 2026-09-05 retirement of graphlet (TERMINOLOGY.md): read graphlet as subgraph. Identifiers such as GraphletId, GraphletRef, and SessionGraphlets are now SubgraphId, SubgraphRef, and SessionSubgraphs, and the graphlets crate is crates/graph/subgraph (code renamed 2026-09-12).*

Findings from a design session, filed 2026-08-09. How the moot layer composes
with a high-latency, multi-transport substrate. Vocabulary follows
[`TERMINOLOGY.md`](https://github.com/merely-made/mere/blob/main/design_docs/TERMINOLOGY.md). The transport-tier counterpart is
retinue's
[mesh scaling and asymmetric routing](https://github.com/merely-made/murm/blob/main/design_docs/2026-08-09_mesh_scaling_and_asymmetric_routing.md);
the two docs came from the same session and share the cost-metered-refusal
pattern (Section 6 here, metering there). The
[radio-scopes-as-moots note](2026-08-12_radio_scopes_as_moots.md) (ratified
2026-08-12) records the first consumer of this model outside mere: retinue's
civic-deployment scopes.

## 1. Grants at the data layer

Grants live at the data layer; the governance layer holds the rules of granting,
never hardwired, plus the actor and participant model.

This is the Stickleback rule stated from the other side. A layer that never
infers authority from transport access or visible membership requires authority
to be carried as data. It is also what lets one moot span iroh, Arti, I2P, and
RNS, because a signed grant is valid however it arrived. Anything that authorized
at the connection layer would pin a moot to one transport.

**Consequence: validity is a relation, not a property.** Two separable questions:

- *Is this grant well-formed and does its chain verify?* Mechanical, universal,
  checkable cold by any peer with no moot rules in hand.
- *Does this moot honor it right now?* Per-moot, time-varying, and two moots can
  legitimately answer differently about the same grant.

Divergent answers are what make federation and region-grafting work. Nothing is
ever simply valid, only honored-here-now.

**Where this bites is partition.** Policy-before-insert evaluates on the
receiving node against whatever revision it holds. At hour-scale propagation, two
nodes will honor different constitution revisions and both be correct, so the
journal is per-node until reconciliation. The governance layer needs a stated
merge rule. Roughly:

- evaluate against the revision current at petition time, accepting that
  late-arriving amendments do not reach back; or
- evaluate at insert time, accepting that the same petition lands differently
  depending on who saw it first.

Both are livable. Left implicit, it gets decided by whichever code path ran.

**The floor cannot be zero.** Something is true before any constitution is read:
how signatures verify, which key founded the moot, how the constitution is
located. These are unvotable by construction. The discipline is not pretending
the floor is empty but keeping it to a paragraph a person can read. The
un-configurable part is the only part nobody gets a say in, so it should be the
most plainly written. This is the same legibility argument that says a space
where the founder holds root should be legible as such before anyone invests.

## 2. Cast and personae

A cast is a related tree of personas derived from a root identity, which may
identify to each other or trade capabilities and reputation under tessera rules.
Reputation cannot persist across roots, and reputation gates Sybil resistance and
tiered capabilities, so spinning up a derived pseudonym is usually preferable to
starting a fresh root.

**Masking is a property of the room, not the persona.** A moot declares what it
accepts: resolves-to-root, resolves-to-root-visible-to-moderators-only,
unlinked-but-nullified, fully unlinked. That is a governed setting the Moot domain
already owns, so the cast needs no separate policy vocabulary. The persona
carries what it can prove; the room decides whether that suffices.

The tree supplies this structurally. HD-style derivation has a linkability knob
per edge: derive so the parent public key regenerates the child and the link is
publicly checkable, or derive hardened and it is not. Cast shape and disclosure
policy end up being the same object.

**Pseudonyms spend; personas earn.** If a persona persists and accrues while a
pseudonym is ephemeral, a pseudonym structurally cannot earn and can only draw
against what the root already holds. Every pseudonym is a draw on a finite
balance, which makes Sybil resistance fall out of the lifecycle rather than being
bolted on. Ten pseudonyms cost ten times as much and produce nothing.

**A cast shrinks the anonymity set rather than growing it.** Several personas
active across overlapping moots deanonymize by intersection, and no cryptography
touches it: activity timing, topic overlap, prose style. The mitigation is
disjointness, not quantity. The instinct that more faces means more cover is
backwards.

**Cross-transport correlation is the sharp edge.** The transports have opposed
metadata postures. RNS announces are public broadcasts of destination hashes with
propagation; Arti and I2P exist to prevent exactly that inference; hole-punching
hands an address to peers directly. Announcing one identity over RNS while using
it over Arti localizes it and destroys the guarantee the onion service was for.
Personae are therefore mandatory rather than convenient, and linkage policy is
constitutional work with nothing upstream to borrow from.

**Sync splits where identity does not.** Range-based set reconciliation assumes a
duplex stream with real throughput and will not run over a 431-byte MDU. Same
data model, same capabilities, different reconciliation protocol per transport
class, with the RNS tier reduced to store-and-forward entry shipping.

## 3. Transferability

Exercise and transfer are separate rights. Holding a grant does not imply the
right to move it; that right is itself granted, and the granter must hold the
right to confer it. This departs from capability systems that fuse the two.

SQL `WITH GRANT OPTION` has the same recursion and documented scar tissue: the
hard part is revocation, not granting. When a grant conferred with transfer
rights has already been moved onward, revoking the original either cascades
through everything downstream or restricts to the direct grant and leaves
orphans holding valid caps. Both are defensible, both surprise people, and
choosing late is expensive. Petitions are already attributed and revertible, so
the journal can walk the chain; this lands as a policy choice rather than a
mechanism problem.

**Persona binding is a stake dial.** Requiring the root identity for an act means
misuse is attributable to everything the root holds, so the grant is backed by
the largest balance in the cast. Permitting a pseudonym backs the same capability
with almost nothing: cheap to abuse, cheap to abandon. The granter is choosing not
only who acts but how much is on the table if it goes wrong.

**Known leak.** If tessera trades within a cast but grants do not, a persona can
inherit the qualification without inheriting the capability, then apply on its own
apparent merits and have the grant reissued, arriving where non-transferability
was meant to prevent. Non-transferable capabilities are only as strong as the
non-transferability of whatever qualifies you for them. The fix is granting
criteria that include something reputation cannot carry, which for
accountability-bound grants is the binding itself.

**Social consequence worth stating:** root-only access to shared canon means canon
can only be written by the unmasked. Correct if shared truth should carry
accountability, and a real filter on who participates.

## 4. Moot as participant

A moot can be a participant, and moots can exist inside moots as nested graphs.

The servitor pattern generalizes one tier up without widening the actor model: a
node bearing a nested graph, holding a personae identity and a grant, acting
through the participant gate.

**Containment sense matters.** A nested graph is containment within a node; a
graphlet is a forme scope over real kernel nodes, peer-scoping and never
containment. A sub-moot could be either, and they yield different federations.
Contained moots are placed inside the parent's graph; scoped moots are views over
shared nodes with no inside. Region-grafting appears to want containment for the
genesis case and scoping for the grafted case.

**Suzerainty forbids the shortcut.** Overlordship without absorbing internal
sovereignty means containment cannot imply authority. Nesting places a moot
without giving the container power over it, so the containment graph and the
grant graph are separate structures over the same nodes. Containment is acyclic
by construction; grants are not, since a contained moot may hold a grant in
something that contains its container. Only the grant graph needs cycle checking,
and it is the one nobody thinks to check.

**A moot holding a personae identity means a moot has a cast.** Section 2
recurses: a moot may present different faces in different parent moots, or join a
gemot under a pseudonym. Federation privacy falls out of the identity model
rather than needing its own mechanism.

## 5. Provenance and attribution

Provenance rules out shell-moot laundering. Even when a moot acts as an agent in
its own right, knowing who did what inside it means the event carries facts about
itself.

The difference from the corporate case is structural rather than procedural. A
shell company works because the decision record is private by default and prying
it out is a legal process with cost and standing requirements. Here attribution is
a property of the apply, so there is no "the moot decided" that fails to
decompose into a petition someone submitted.

**Scale runs the same way.** A moot's membership is its anonymity set. A small
moot acting outwardly narrows the actor to its members, and event facts (grant
exercised, time, what changed) cut further. Laundering needs a large moot to hide
in, and a large moot has accumulated tessera and standing it will not spend
covering for one member. The economics run against it at both ends.

**What remains live is legibility, not provenance.** The record exists inside the
sub-moot; whether a parent can read it is a read grant, and suzerainty denies the
parent that by default, since reading every internal journal is absorption. So a
parent sees a well-attributed act by a participant whose internal attribution it may
have no standing to inspect.

This reads as a governed setting rather than a hole. A gemot's admission criteria
can require member moots to expose outward-act attribution as a condition of
joining: a rule of granting, decided per assembly, and legible before anyone
invests.

**Residual, not specific to moots:** provenance names the submitter, not the
instigator. A participant petitioning under instruction is attributed and whoever
directed them is not. No record-keeping system solves this.

## 6. Cross-cutting patterns

Three observations that surfaced at more than one layer and may be worth stating
once, centrally, rather than per subsystem.

**Cost-metered refusal to carry is one mechanism at four layers.** Airtime budget
on announces, forwarder policy at island boundaries, non-replication in place of
revocation, pinning determining whether a moot exists. Not four subsystems that
rhyme; one law surfacing at transport, routing, data, and social layers.
(Retinue's channel-murmuration design adds a fifth surface: radio dwell time
spent across channels. See the reference above.)

**Nothing persists by default.** Announces decay, paths expire, moots dissolve
when unpinned. Existence is continuous assertion at every level. Most systems
guarantee persistence somewhere and bolt deletion on top, which is why revocation
kept turning out to be the wrong word: the correct concept is non-participation,
and it needs no deletion authority because permanence was never on offer.

**Emergence decides where boundaries are; declaration decides what they are
called.** Islands are the shadow of a cost function and terrain does the
partitioning; people supply names and constitutions. Every failure mode
encountered was one invading the other: political geography defining RF islands,
antenna reach defining moot membership, transport contribution accruing into
membership.

## Open questions

- Partition merge rule for divergent policy revisions (Section 1).
- Cascade versus restrict on revocation of transferred grants (Section 3).
- Whether a moot's personas may trade tessera among themselves on the same terms
  a person's may (Section 4).
- Linkage policy across transports: which correlations a constitution may permit,
  and whether default disjointness is enforceable or only advisory (Section 2).
- Whether region-grafting uses nested graphs, graphlets, or both, and what
  determines which (Section 4).
