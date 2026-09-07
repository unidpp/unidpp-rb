# frozen_string_literal: true

module Unidpp
  module Registry
    # Register metadata with ISO 19135 governance roles: the register
    # owner, register manager and control body for this (sub)register.
    # FERIN registers federate as siblings — no register is the universal
    # envelope.
    class Register < Lutaml::Model::Serializable
      attribute :register_id, :string   # FERIN register identifier
      attribute :name, :string
      attribute :register_owner, :string
      attribute :register_manager, :string
      attribute :control_body, :string
      attribute :homepage, :string

      json do
        map "register_id", to: :register_id
        map "name", to: :name, render_nil: false
        map "register_owner", to: :register_owner, render_nil: false
        map "register_manager", to: :register_manager, render_nil: false
        map "control_body", to: :control_body, render_nil: false
        map "homepage", to: :homepage, render_nil: false
      end

      yaml do
        map "register_id", to: :register_id
        map "name", to: :name, render_nil: false
        map "register_owner", to: :register_owner, render_nil: false
        map "register_manager", to: :register_manager, render_nil: false
        map "control_body", to: :control_body, render_nil: false
        map "homepage", to: :homepage, render_nil: false
      end
    end
  end
end
