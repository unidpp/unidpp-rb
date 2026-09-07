# frozen_string_literal: true

module Unidpp
  # Subject capability classes (I8: twin testimonial by default, sensorial
  # by exception). A profile's requirements must be satisfiable by the
  # class its subjects belong to — demanding live freshness from an S0
  # product is an unsatisfiable profile.
  #
  #   S0 silent          testimony-only (no connectivity, no keys)
  #   S1 passive-auth    NFC chip / PUF / IEC 61406 identity link
  #   S2 logged-contact  dumps on physical read, no comms
  #   S3 connected       full edge segments
  module CapabilityClass
    ORDER = %w[S0 S1 S2 S3].freeze

    module_function

    # @param required [String] profile's minimum required class
    # @param actual [String] the subject's capability class
    # @return [Boolean] whether +actual+ meets or exceeds +required+
    def satisfies?(required, actual)
      ORDER.index(actual) >= ORDER.index(required)
    end
  end

  # Applicability axis values of a profile: composition is three-axial —
  # jurisdiction x sector x characteristic (I10). Characteristic profiles
  # attach by predicate on twin facts (age, material content, heritage
  # status, market status) rather than by law-of-place or industry.
  class ProfileAxes < Lutaml::Model::Serializable
    attribute :jurisdictions, :string, collection: true, default: -> { [] }
    attribute :sectors, :string, collection: true, default: -> { [] }
    attribute :characteristics, :string, collection: true, default: -> { [] }

    json do
      map "jurisdictions", to: :jurisdictions, render_nil: false
      map "sectors", to: :sectors, render_nil: false
      map "characteristics", to: :characteristics, render_nil: false
    end

    yaml do
      map "jurisdictions", to: :jurisdictions, render_nil: false
      map "sectors", to: :sectors, render_nil: false
      map "characteristics", to: :characteristics, render_nil: false
    end

    def empty?
      jurisdictions.empty? && sectors.empty? && characteristics.empty?
    end
  end

  # One predicate of a profile's trigger (I10 / I12). Predicates are
  # evaluated against twin facts by the subject's custodian — locally,
  # without enumeration. Time predicates are clock-fired: an object
  # becoming >100 years old is an applicability event no human declares.
  class TriggerPredicate < Lutaml::Model::Serializable
    OPERATORS = %w[eq neq gt gte lt lte contains exists before after].freeze
    # Fact-path suffixes that make a predicate time-derived (clock-fired).
    TIME_SUBJECT_SUFFIXES = %w[_at _date _years _age].freeze

    attribute :subject, :string          # fact path, e.g. "object.age_years"
    attribute :operator, :string, values: OPERATORS
    attribute :value, :string
    attribute :cites, :string            # clause-level provenance URN

    json do
      map "subject", to: :subject
      map "operator", to: :operator
      map "value", to: :value, render_nil: false
      map "cites", to: :cites, render_nil: false
    end

    yaml do
      map "subject", to: :subject
      map "operator", to: :operator
      map "value", to: :value, render_nil: false
      map "cites", to: :cites, render_nil: false
    end

    # @return [Boolean] whether this predicate is time-derived and can
    #   fire on the passage of time alone
    def time_fired?
      time_operator? ||
        TIME_SUBJECT_SUFFIXES.any? { |suffix| subject.to_s.end_with?(suffix) }
    end

    # Evaluates the predicate against a facts document (a Hash with
    # dotted-path-resolvable keys, e.g. {"object" => {"age_years" => 120}}).
    #
    # @param facts [Hash]
    # @return [Boolean]
    def matches?(facts)
      actual = TriggerPredicate.resolve_path(facts, subject)
      return operator == "exists" ? !actual.nil? : false if actual.nil?

      case operator
      when "exists" then true
      when "eq"     then compare_eq(actual)
      when "neq"    then !compare_eq(actual)
      when "contains" then contains_match?(actual)
      when "gt", "gte", "lt", "lte" then numeric_compare(actual)
      when "before", "after" then time_compare(actual)
      else false
      end
    end

    # @return [String] human-readable summary, for drift/conformance
    #   reports
    def description
      "#{subject} #{operator} #{value}"
    end

    def self.resolve_path(facts, path)
      path.to_s.split(".").reduce(facts) do |node, key|
        break nil unless node.is_a?(Hash) || node.is_a?(Array)

        node.is_a?(Array) ? node.map { |e| e[key] if e.is_a?(Hash) }.compact : node[key]
      end
    end

    private

    def time_operator?
      %w[before after].include?(operator)
    end

    def compare_eq(actual)
      if numeric?(actual) && numeric?(value)
        actual.to_f == value.to_f
      else
        actual.to_s == value.to_s
      end
    end

    # contains-match against array or scalar facts (distinct from the
    # lutaml-generated +contains?+ enum predicate on the operator).
    def contains_match?(actual)
      if actual.is_a?(Array)
        actual.map(&:to_s).include?(value.to_s)
      else
        actual.to_s.include?(value.to_s)
      end
    end

    def numeric_compare(actual)
      return false unless numeric?(actual) && numeric?(value)

      a = actual.to_f
      v = value.to_f
      case operator
      when "gt"  then a > v
      when "gte" then a >= v
      when "lt"  then a < v
      when "lte" then a <= v
      end
    end

    def time_compare(actual)
      a = to_time(actual)
      v = to_time(value)
      return false if a.nil? || v.nil?

      operator == "before" ? a < v : a > v
    end

    def numeric?(v)
      Float(v.to_s) != nil
    rescue ArgumentError, TypeError
      false
    end

    def to_time(v)
      return v if v.is_a?(Time) || v.is_a?(DateTime) || v.is_a?(Date)

      DateTime.parse(v.to_s)
    rescue ArgumentError, TypeError
      nil
    end
  end

  # Binding of a cryptographic suite to a profile (I9/I10: jurisdictional
  # crypto suites are part of the profile, not the platform). The same
  # payload carries multiple signatures; verifiers check only what their
  # profile-scoped acceptance policy requires.
  class CryptoSuiteBinding < Lutaml::Model::Serializable
    USES = %w[sign hash kem transport].freeze
    PHASES = %w[primary composite post-quantum].freeze

    attribute :suite_id, :string          # registry item id (crypto-suite subregister)
    attribute :jurisdiction, :string
    attribute :use, :string, values: USES
    attribute :phase, :string, values: PHASES, default: -> { "primary" }

    json do
      map "suite_id", to: :suite_id
      map "jurisdiction", to: :jurisdiction
      map "use", to: :use
      map "phase", to: :phase
    end

    yaml do
      map "suite_id", to: :suite_id
      map "jurisdiction", to: :jurisdiction
      map "use", to: :use
      map "phase", to: :phase
    end

    def post_quantum?
      phase == "post-quantum"
    end
  end

  # The profile manifest (L2 / I10): a profile is a registered, versioned
  # lens placed on the neutral core. It binds axes (jurisdiction x sector
  # x characteristic), trigger predicates, the minimum subject capability
  # class it can be served for, its crypto-suite bindings, the data points
  # it requires (references into the semantic registry), languages, and
  # its legal effective window. Registered transforms and trust
  # requirements ride the registry items referenced here.
  #
  # (De)serialization is generated by lutaml-model from the attribute +
  # mapping declarations below — no hand-rolled to_h / from_h.
  class ProfileManifest < Lutaml::Model::Serializable
    CAPABILITY_CLASSES = CapabilityClass::ORDER

    attribute :profile_id, :string       # registry item identifier
    attribute :version, :string          # registry item version pin
    attribute :register, :string         # FERIN register that holds the profile
    attribute :owner, :string            # regulator / profile owner
    attribute :legal_basis, :string      # citation URI of the applicable law
    attribute :axes, ProfileAxes
    attribute :triggers, TriggerPredicate, collection: true, default: -> { [] }
    attribute :capability_class, :string, values: CAPABILITY_CLASSES,
                                           default: -> { "S0" }
    attribute :crypto_suites, CryptoSuiteBinding, collection: true,
                                                  default: -> { [] }
    # Data points required by the profile: (register, item, version)
    # references into the semantic registry, as resolvable URIs.
    attribute :data_points, :string, collection: true, default: -> { [] }
    attribute :languages, :string, collection: true, default: -> { [] }
    attribute :effective_from, "Lutaml::Model::Type::DateTime"
    attribute :effective_until, "Lutaml::Model::Type::DateTime"
    # Resolution / traversal exposure (I12): confidential profiles are
    # non-public register items; resolution scope limits the resolver.
    attribute :resolution, :string,
               values: %w[none national restricted public],
               default: -> { "public" }
    attribute :confidential, :boolean, default: -> { false }

    json do
      map "profile_id", to: :profile_id
      map "version", to: :version
      map "register", to: :register, render_nil: false
      map "owner", to: :owner, render_nil: false
      map "legal_basis", to: :legal_basis, render_nil: false
      map "axes", to: :axes, render_nil: false
      map "triggers", to: :triggers, render_nil: false
      map "capability_class", to: :capability_class
      map "crypto_suites", to: :crypto_suites, render_nil: false
      map "data_points", to: :data_points, render_nil: false
      map "languages", to: :languages, render_nil: false
      map "effective_from", to: :effective_from, render_nil: false
      map "effective_until", to: :effective_until, render_nil: false
      map "resolution", to: :resolution
      map "confidential", to: :confidential
    end

    yaml do
      map "profile_id", to: :profile_id
      map "version", to: :version
      map "register", to: :register, render_nil: false
      map "owner", to: :owner, render_nil: false
      map "legal_basis", to: :legal_basis, render_nil: false
      map "axes", to: :axes, render_nil: false
      map "triggers", to: :triggers, render_nil: false
      map "capability_class", to: :capability_class
      map "crypto_suites", to: :crypto_suites, render_nil: false
      map "data_points", to: :data_points, render_nil: false
      map "languages", to: :languages, render_nil: false
      map "effective_from", to: :effective_from, render_nil: false
      map "effective_until", to: :effective_until, render_nil: false
      map "resolution", to: :resolution
      map "confidential", to: :confidential
    end

    # A profile with no trigger predicates applies to every subject of
    # its axes; otherwise every predicate must match (conjunction).
    #
    # @param facts [Hash] twin facts document
    # @return [Boolean]
    def applies_to?(facts)
      triggers.all? { |predicate| predicate.matches?(facts) }
    end

    # @param subject_capability [String] S0..S3 of the subject
    # @return [Boolean] satisfiability of this profile for that class
    def satisfiable_for?(subject_capability)
      CapabilityClass.satisfies?(capability_class, subject_capability)
    end

    # Legal effective window at time +t+.
    # @param t [Time, DateTime]
    # @return [Boolean]
    def effective_at?(t)
      t = to_datetime(t)
      (!effective_from || t >= effective_from) &&
        (!effective_until || t < effective_until)
    end

    def jurisdiction_profile?
      !axes.jurisdictions.empty?
    end

    def characteristic_profile?
      !axes.characteristics.empty?
    end

    def time_triggered?
      triggers.any?(&:time_fired?)
    end

    private

    def to_datetime(t)
      t.is_a?(DateTime) ? t : DateTime.parse(t.to_s)
    end
  end
end
