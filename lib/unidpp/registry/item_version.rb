# frozen_string_literal: true

module Unidpp
  module Registry
    # One version of a registry item with its ISO 19135 lifecycle status.
    # Versions are immutable once registered; status and supersession
    # links express the lifecycle (valid / superseded / retired).
    class ItemVersion < Lutaml::Model::Serializable
      STATUSES = %w[valid superseded retired].freeze

      attribute :version, :string
      attribute :status, :string, values: STATUSES
      # Effective window of this version. An open effective_until is
      # derived from the successor's effective_from when absent.
      attribute :effective_from, "Lutaml::Model::Type::DateTime"
      attribute :effective_until, "Lutaml::Model::Type::DateTime"
      attribute :registered_at, "Lutaml::Model::Type::DateTime"
      attribute :superseded_by_version, :string
      attribute :notes, :string

      json do
        map "version", to: :version
        map "status", to: :status
        map "effective_from", to: :effective_from, render_nil: false
        map "effective_until", to: :effective_until, render_nil: false
        map "registered_at", to: :registered_at, render_nil: false
        map "superseded_by_version", to: :superseded_by_version, render_nil: false
        map "notes", to: :notes, render_nil: false
      end

      yaml do
        map "version", to: :version
        map "status", to: :status
        map "effective_from", to: :effective_from, render_nil: false
        map "effective_until", to: :effective_until, render_nil: false
        map "registered_at", to: :registered_at, render_nil: false
        map "superseded_by_version", to: :superseded_by_version, render_nil: false
        map "notes", to: :notes, render_nil: false
      end

      def valid?
        status == "valid"
      end

      def superseded?
        status == "superseded"
      end

      def retired?
        status == "retired"
      end

      # @param t [Time, DateTime]
      # @param until_time [DateTime, nil] resolved window end (explicit or
      #   derived from the successor)
      # @return [Boolean] this version was in force at +t+
      def in_force_at?(t, until_time: effective_until)
        t = t.is_a?(DateTime) ? t : DateTime.parse(t.to_s)
        return false if effective_from && t < effective_from
        return false if until_time && t >= until_time

        true
      end
    end
  end
end
