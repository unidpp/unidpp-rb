# frozen_string_literal: true

module Unidpp
  module Registry
    # Registry client: item lookup with version+status, supersession
    # resolution, and applicability as-of queries over any Store. The
    # client is read-only — registration (proposals, public review,
    # control-body decisions) belongs to the register operator's own
    # tooling; consumers resolve references.
    class Client
      class ItemNotFoundError < Unidpp::Error; end
      class NoValidVersionError < Unidpp::Error; end

      attr_reader :store

      # @param store [Store]
      def initialize(store:)
        @store = store
      end

      # @return [Register, nil]
      def register
        store.register
      end

      # @return [Array<Item>]
      def items
        store.items
      end

      # @param register [String, nil] optional register scope
      # @param identifier [String] item identifier
      # @return [Item, nil]
      def item(identifier, register: nil)
        store.items.find do |i|
          i.identifier == identifier && (register.nil? || i.register == register)
        end
      end

      # @param identifier [String]
      # @return [Item]
      # @raise [ItemNotFoundError]
      def item!(identifier, register: nil)
        scope = register ? " in register #{register.inspect}" : ""
        item(identifier, register: register) ||
          raise(ItemNotFoundError,
                "no registry item #{identifier.inspect}#{scope}")
      end

      # Version-pinned lookup: the exact version when given, otherwise the
      # version currently in force.
      #
      # @param identifier [String]
      # @param version [String, nil]
      # @return [ItemVersion]
      # @raise [ItemNotFoundError, Item::UnknownVersionError]
      def version_of(identifier, version: nil, register: nil)
        found = item!(identifier, register: register)
        version ? found.version!(version) : current_version_of(found)
      end

      # @param item [Item]
      # @return [ItemVersion]
      # @raise [NoValidVersionError] when no version is in force
      def current_version_of(item)
        item.current_version ||
          raise(NoValidVersionError, "#{item.identifier} has no valid version")
      end

      # Supersession resolution: the terminal version of the chain.
      #
      # @param identifier [String]
      # @return [ItemVersion]
      # @raise [ItemNotFoundError]
      def resolve(identifier, register: nil)
        supersession_chain(identifier, register: register).last
      end

      # @param identifier [String]
      # @param from [String, nil] chain start version
      # @return [Array<ItemVersion>] chain in supersession order
      # @raise [ItemNotFoundError]
      def supersession_chain(identifier, from: nil, register: nil)
        item!(identifier, register: register).supersession_chain(from: from)
      end

      # Point-in-time item state: the version in force at +t+.
      #
      # @param identifier [String]
      # @param as_of [Time, DateTime]
      # @return [ItemVersion, nil]
      # @raise [ItemNotFoundError]
      def version_as_of(identifier, as_of:, register: nil)
        item!(identifier, register: register).in_force_at(as_of)
      end

      # -- applicability --------------------------------------------------

      # @param subject [String] canonical product/type identity
      # @return [Array<ApplicabilityBinding>]
      def bindings_for(subject)
        store.bindings.select { |b| b.subject == subject }
      end

      # The legal as-of query: which profiles applied to +subject+ at +t+.
      # Retroactive bindings apply from their effective_from even when
      # registered later; non-retroactive ones only from registered_at.
      #
      # @param subject [String]
      # @param as_of [Time, DateTime]
      # @return [Array<ApplicabilityBinding>]
      def applicable_profiles(subject, as_of:)
        bindings_for(subject).select { |b| b.applies_at?(as_of) }
      end

      # The same query resolved to version-pinned profile items.
      #
      # @param subject [String]
      # @param as_of [Time, DateTime]
      # @return [Array<Item>] profile items applicable at +t+
      def applicable_profile_items(subject, as_of:)
        applicable_profiles(subject, as_of: as_of).map do |binding|
          item(binding.profile_item, register: binding.register)
        end.compact
      end

      # The manifests of the profiles applicable at +t+ (nil entries are
      # skipped for bindings whose item carries no embedded manifest).
      #
      # @param subject [String]
      # @param as_of [Time, DateTime]
      # @return [Array<ProfileManifest>]
      def applicable_manifests(subject, as_of:)
        applicable_profiles(subject, as_of: as_of).filter_map do |binding|
          found = item(binding.profile_item, register: binding.register)
          found&.manifest
        end
      end
    end
  end
end
