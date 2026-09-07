# frozen_string_literal: true

module Unidpp
  module Registry
    # Store interface — the seam between the registry client and a source
    # of register content (local files for tests and offline mirrors; an
    # HTTP adapter against a live FERIN register endpoint can implement
    # the same three methods without touching the client).
    class Store
      # @return [Array<Item>] all items in the store
      def items
        raise NotImplementedError, "#{self.class} must implement #items"
      end

      # @return [Array<ApplicabilityBinding>] all applicability bindings
      def bindings
        raise NotImplementedError, "#{self.class} must implement #bindings"
      end

      # @return [Register, nil] register metadata when available
      def register
        raise NotImplementedError, "#{self.class} must implement #register"
      end
    end
  end
end
