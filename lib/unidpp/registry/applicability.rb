# frozen_string_literal: true

module Unidpp
  module Registry
    # Applicability binding (source invariant 9): profile-set growth is
    # dated binding, not new identity. Adding a profile to an existing
    # subject is a registry applicability event with an effective window
    # and a retroactivity flag; manifest history is as-of-reconstructable.
    #
    # Retroactivity semantics: a retroactive binding legally backdates —
    # it applies from its effective_from even though registered later
    # (end-of-waste style re-qualification, corrected as-of state). A
    # non-retroactive binding cannot impose obligations for times before
    # the authority declared it (registered_at).
    class ApplicabilityBinding < Lutaml::Model::Serializable
      attribute :subject, :string        # canonical product/type identity
      attribute :profile_item, :string   # registry item identifier
      attribute :register, :string       # register holding the profile
      attribute :profile_version, :string
      attribute :effective_from, "Lutaml::Model::Type::DateTime"
      attribute :effective_until, "Lutaml::Model::Type::DateTime"
      attribute :registered_at, "Lutaml::Model::Type::DateTime"
      attribute :retroactive, :boolean, default: -> { false }

      json do
        map "subject", to: :subject
        map "profile_item", to: :profile_item
        map "register", to: :register, render_nil: false
        map "profile_version", to: :profile_version, render_nil: false
        map "effective_from", to: :effective_from, render_nil: false
        map "effective_until", to: :effective_until, render_nil: false
        map "registered_at", to: :registered_at, render_nil: false
        map "retroactive", to: :retroactive
      end

      yaml do
        map "subject", to: :subject
        map "profile_item", to: :profile_item
        map "register", to: :register, render_nil: false
        map "profile_version", to: :profile_version, render_nil: false
        map "effective_from", to: :effective_from, render_nil: false
        map "effective_until", to: :effective_until, render_nil: false
        map "registered_at", to: :registered_at, render_nil: false
        map "retroactive", to: :retroactive
      end

      # Legal as-of semantics.
      #
      # @param t [Time, DateTime]
      # @return [Boolean] the binding applied to the subject at +t+
      def applies_at?(t)
        t = t.is_a?(DateTime) ? t : DateTime.parse(t.to_s)
        return false if effective_from && t < effective_from
        return false if effective_until && t >= effective_until
        return false if !retroactive? && registered_at && t < registered_at

        true
      end

      # @return [Boolean]
      def retroactive?
        retroactive == true
      end
    end
  end
end
