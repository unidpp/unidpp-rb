# frozen_string_literal: true

require "json"

module Unidpp
  # Deterministic canonical JSON used for commitments (event-log chaining,
  # blind-edge parent commitments).
  #
  # The source document is always the *framework-generated* serialization
  # of a Lutaml::Model object (to_json); this module only imposes a
  # canonical key order on top of that output so that identical logical
  # documents always hash identically, regardless of hash insertion order.
  # It is a canonicalizer, not a serializer: no model mappings live here.
  module CanonicalJson
    module_function

    # @param serializable [Lutaml::Model::Serializable]
    # @return [String] canonical JSON with all object keys sorted
    #   (recursively).
    def of(serializable)
      sorted(JSON.parse(serializable.to_json)).to_json
    end

    # @param obj [Object] parsed JSON structure
    # @return [Object] same structure with every Hash's keys sorted
    def sorted(obj)
      case obj
      when Hash
        obj.keys.sort.to_h { |k| [k, sorted(obj[k])] }
      when Array
        obj.map { |v| sorted(v) }
      else
        obj
      end
    end
  end
end
