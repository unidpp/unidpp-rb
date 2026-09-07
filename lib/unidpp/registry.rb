# frozen_string_literal: true

module Unidpp
  # FERIN / ISO 19135-style federated registry access (framework layer L3,
  # seam S4/S5): every data point, profile, transform, crypto suite and
  # unit is defined ONCE in a register — principal register plus
  # federated subregisters with 19135 governance roles — and every item
  # has a lifecycle (valid / superseded / retired) and versioned
  # supersession chains. Applicability bindings carry effective windows
  # with retroactivity flags, which is what makes "which profiles applied
  # at T" answerable as a legal as-of query.
  module Registry
    autoload :Register,              "unidpp/registry/register"
    autoload :ItemVersion,           "unidpp/registry/item_version"
    autoload :Item,                  "unidpp/registry/item"
    autoload :ApplicabilityBinding,  "unidpp/registry/applicability"
    autoload :Store,                 "unidpp/registry/store"
    autoload :FileStore,             "unidpp/registry/file_store"
    autoload :Client,                "unidpp/registry/client"
  end
end
