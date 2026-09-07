# unidpp-rb

UniDPP Ruby library (github.com/unidpp).
License: MIT.

`unidpp` is the Ruby library of the UniDPP international Digital Product
Passport framework: scheme-agnostic product identifiers, profile
manifests, typed relationship edges, hash-chained append-only event logs
with salted commitments, graded-trust verdicts, quantities with
registered unit URIs, and a FERIN / ISO 19135-style federated registry
client with supersession chains and applicability as-of queries.

The framework layering and design invariants implemented here follow the
`the UniDPP design framework` core (invariants I1–I14, seams S1–S12) — the library
is the Ruby realization of the neutral core plus the registry seam, not
an EU-profile wrapper.

## Installation

 gem install unidpp # or: gem "unidpp" in a Gemfile

Requires Ruby >= 3.0 and `lutaml-model` (~> 0.8).

## Modules

| Module | the UniDPP design framework anchors |
|---|---|
| `Unidpp::ProductIdentifier` | L0 identity (I1, I3): GS1 Digital Link (AI 01/10/21), GS1 element strings, ISO/IEC 15459 SSCC, GB/T 33993-style national carrier wrappers, URNs (incl. `urn:epc:id:sgtin/sscc` reconstruction with check-digit computation); granularity ladder model/batch/item |
| `Unidpp::Gs1` | GS1 key arithmetic: application identifiers, element-string parsing, mod-10 check digit |
| `Unidpp::ProfileManifest` (+ `ProfileAxes`, `TriggerPredicate`, `CryptoSuiteBinding`, `CapabilityClass`) | L2 profiles (I10): jurisdiction × sector × characteristic axes, predicate triggers incl. clock-fired time predicates, capability classes S0–S3 with satisfiability, crypto-suite bindings with migration phases, registry data-point references, effective windows, resolution/confidentiality exposure |
| `Unidpp::PassportLink` (+ `LinkInterval`) | I5 relationship algebra R1–R7: installation binding schema (method/slot/pairing/alteration/recoverability), visibility classes (public/restricted/blind/escrowed), salted parent commitments — proof-of-binding without knowledge-of-parent (I12) |
| `Unidpp::Event`, `Unidpp::EventLog` | I4 append-only event sourcing: the E1–E15 post-sale event taxonomy with per-kind appender authorization, graded trust markers, SHA-256 hash chain with per-entry salt (S6: logs anchor commitments, never facts), as-of snapshot views, reveal/inclusion-consistency |
| `Unidpp::Verdict` | I9/I13: three verification readings (evidentiary / current_state / cryptographic), explicit freshness classes (fresh / stale / offline_degraded / unavailable), coverage reports |
| `Unidpp::Quantity` | units chain: value + registered unit URI (UnitsDB/UnitsML), strict-unit arithmetic (no implicit conversion — conversion is a registered transform), GUM uncertainty propagation, ILAC-G8 shared-risk agreement |
| `Unidpp::Registry` | L3 registry (I2, I6; seams S4/S5): `Register` (19135 governance roles), `Item`/`ItemVersion` (valid/superseded/retired lifecycle, supersession chains, point-in-time version state, version-pinned embedded manifests), `ApplicabilityBinding` (effective windows, retroactivity), `Store` interface + `FileStore` (local YAML/JSON adapter), `Client` (lookup, resolution, as-of queries) |

## Usage

```ruby
require "unidpp"

# Identity — one subject, one identity (parsed, validated, normalized)
id = Unidpp::ProductIdentifier.parse(
 "https://id.example.com/01/09506000134352/10/ABC-123/21/9876543")
id.canonical # => "(01)09506000134352(10)ABC-123(21)9876543"
id.granularity # => "item"

# Profiles — a registered, versioned lens on the neutral core
manifest = Unidpp::ProfileManifest.new(
 profile_id: "eu-espr-textiles", version: "1.0.0",
 axes: Unidpp::ProfileAxes.new(jurisdictions: ["EU"], sectors: ["textiles"]),
 capability_class: "S1",
 triggers: [Unidpp::TriggerPredicate.new(
 subject: "object.age_years", operator: "gte", value: "100")])
manifest.applies_to?({ "object" => { "age_years" => 120 } }) # => true
manifest.satisfiable_for?("S0") # => false

# Relationship edges — installation with a blind parent commitment
battery = Unidpp::ProductIdentifier.parse("https://id.example.com/01/09506000134352/21/BAT-77")
car = Unidpp::ProductIdentifier.parse("https://id.example.com/01/06901234000016/21/CAR-1")
link = Unidpp::PassportLink.install(child: battery, parent: car,
 visibility: "blind", slot_id: "battery-slot-1",
 recoverability: "harvestable")
link.parent # => nil (hidden)
link.proves_parent?(car) # => true (salted commitment check)

# Event log — append-only, hash-chained, salted commitments
log = Unidpp::EventLog.new(subject: car.canonical_id)
entry = log.append(Unidpp::Event.new(
 event_type: "upgrade.install", occurred_at: "2027-03-01T10:00:00+00:00",
 actor_role: "installer", subject: car.canonical_id,
 payload: { "child" => battery.canonical_id }))
log.verify! # raises Unidpp::EventLog::IntegrityError when tampered
log.head # => anchored commitment (what a transparency log anchors)
log.as_of("2027-06-01T00:00:00+00:00") # notarized snapshot

# Registry — FERIN/19135 items, supersession, applicability as-of
client = Unidpp::Registry::Client.new(
 store: Unidpp::Registry::FileStore.new("path/to/registry"))
client.version_of("eu-espr-textiles") # current valid version
client.resolve("eu-espr-textiles").version # terminal of the chain
client.version_as_of("eu-espr-textiles", as_of: t) # version in force at t
client.applicable_manifests(car.canonical_id, as_of: t) # which profiles applied at t
```

## Registry store layout

`Unidpp::Registry::FileStore` accepts a directory (one item per file,
glossarist-dataset style) or a single consolidated JSON/YAML document:

 registry/
 register.yaml # Register metadata (19135 governance roles)
 items/*.yaml # one Item per file (profile items embed their manifest)
 bindings/*.yaml # ApplicabilityBinding lists (subject -> profile windows)

An HTTP adapter against a live FERIN register endpoint only needs to
implement `Unidpp::Registry::Store` (`#items`, `#bindings`, `#register`)
— the client is store-agnostic.

## Design rules

- **lutaml-model for all serialization.** Every wire format (JSON/YAML)
 is generated from `attribute` + `mapping` declarations; there is no
 hand-rolled `to_h`/`from_h` anywhere. `Unidpp::CanonicalJson` only
 imposes deterministic key order on framework output for commitment
 hashing — it is a canonicalizer, not a serializer.
- **Autoload-only loading.** `lib/unidpp.rb` (and `lib/unidpp/registry.rb`
 for the registry namespace) declare every autoload; there is no
 `require_relative` inside `lib/`.
- **Enum predicates come from the framework.** lutaml-model generates
 `?` predicates for enumerated values (`item?`, `blind?`,
 `evidentiary?`, `profile?`, ...); domain predicates beyond enums
 (`valid_keys?`, `applies_to?`, `proves_parent?`, ...) are hand-written.
- **No implicit unit conversion.** Quantity arithmetic requires identical
 registered unit URIs; conversion is a registered transform, never a
 library-side factor.
- **Defaults render deterministically on hashed models.** `Event`
 mappings use `render_default: true` so the committed canonical form
 does not depend on assignment state.

## Development

 bundle install
 bundle exec rspec # 132 examples
 bundle exec rake # same, via Rake
 gem build unidpp.gemspec

Fixtures live in `spec/fixtures/` — the registry directory is a worked
example of a register with supersession chains and retroactive
applicability bindings.

## Status

P1 groundwork per ``: model + event log + registry
client in Ruby; the canonical algorithms live in `unidpp-core` (Rust) and
this gem mirrors their semantics for the Ruby ecosystem (glossarist
bridge, expressir/CDDAL hooks to follow).
