# frozen_string_literal: true

require "securerandom"

module Unidpp
  # Typed lifecycle event (I4: append-only event sourcing; the event log
  # is the authoritative record). The post-first-sale taxonomy E1–E15
  # with the roles authorized to append each kind — nothing is ever
  # edited in place; every change is an appended event.
  class Event < Lutaml::Model::Serializable
    # event type -> roles that may append it (the appender column of the
    # taxonomy; "any" means any custodian-role actor per profile rules).
    TAXONOMY = {
      "custody.transfer"    => %w[custodian counterparty],
      "part.replace"        => %w[repairer],
      "repair.perform"      => %w[repairer],
      "product.modify"      => %w[modifier],
      "software.update"     => %w[eo service],
      "feature.unlock"      => %w[eo service],
      "upgrade.install"     => %w[installer],
      "refurbish.perform"   => %w[refurbisher],
      "consumable.replace"  => %w[custodian repairer eo service installer],
      "recall.campaign"     => %w[regulator eo],
      "correction.record"   => %w[eo manufacturer certifier],
      "status.change"       => %w[regulator eo],
      "flag.security"       => %w[authority registrar],
      "decompose.perform"   => %w[recycler transformer],
      "inspection.stamp"    => %w[verifier certifier],
      "milestone.record"    => %w[device custodian],
    }.freeze

    EVENT_TYPES = TAXONOMY.keys.freeze

    ACTOR_ROLES = TAXONOMY.values.flatten.uniq.freeze

    # Graded trust markers (I9 / source invariant 8: trust is graded, not
    # mandated — every event carries one).
    TRUST_MARKERS = %w[
      unsigned self_declared third_party_attested multi_signed log_anchored
    ].freeze

    class UnauthorizedAppenderError < Unidpp::Error; end

    # event_id has deliberately NO default: the log assigns it exactly
    # once at append, so the committed canonical form is stable whether
    # the event was hand-built or round-tripped.
    attribute :event_id, :string
    attribute :event_type, :string, values: EVENT_TYPES
    attribute :occurred_at, "Lutaml::Model::Type::DateTime"
    attribute :actor, :string               # named actor
    attribute :actor_role, :string, values: ACTOR_ROLES
    # Canonical identity of the subject whose log this event appends to.
    attribute :subject, :string
    # Free event payload (string-keyed, scalar values); canonicalized by
    # the event log for commitments.
    attribute :payload, :hash, default: -> { {} }
    attribute :trust_marker, :string, values: TRUST_MARKERS,
                                      default: -> { "unsigned" }

    # Defaulted attributes render always (render_default: true) so that
    # the canonical JSON hashed into commitments does not depend on
    # whether the value was explicitly assigned or materialized.
    json do
      map "event_id", to: :event_id
      map "event_type", to: :event_type
      map "occurred_at", to: :occurred_at
      map "actor", to: :actor, render_nil: false
      map "actor_role", to: :actor_role
      map "subject", to: :subject
      map "payload", to: :payload, render_default: true
      map "trust_marker", to: :trust_marker, render_default: true
    end

    yaml do
      map "event_id", to: :event_id
      map "event_type", to: :event_type
      map "occurred_at", to: :occurred_at
      map "actor", to: :actor, render_nil: false
      map "actor_role", to: :actor_role
      map "subject", to: :subject
      map "payload", to: :payload, render_default: true
      map "trust_marker", to: :trust_marker, render_default: true
    end

    # Appender authorization: the actor role must be among the roles the
    # taxonomy allows for this event kind (I4 discipline — custody
    # transfer is appended by the custodian, a recall by the regulator,
    # and so on).
    #
    # @return [Boolean]
    def authorized_appender?
      TAXONOMY.fetch(event_type, []).include?(actor_role)
    end

    # @raise [UnauthorizedAppenderError]
    def authorize_appender!
      unless authorized_appender?
        raise UnauthorizedAppenderError,
              "#{actor_role} may not append #{event_type}"
      end
    end
  end
end
