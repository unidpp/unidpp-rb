# frozen_string_literal: true

require "json"
require "yaml"

module Unidpp
  module Registry
    # Local JSON/YAML store adapter: registry content read from a
    # directory or a single consolidated document. All (de)serialization
    # of items, bindings and register metadata goes through lutaml-model
    # (Item.from_yaml / from_json, etc.); this adapter only locates and
    # reads raw documents.
    #
    # Directory layout (glossarist-dataset style, one item per file):
    #
    #   <path>/register.yaml      Register metadata
    #   <path>/items/*.yaml       one Item per file
    #   <path>/bindings/*.yaml    one ApplicabilityBinding or a
    #                             bindings: [...] list per file
    #
    # Single-file layout (JSON or YAML): one document with the keys
    # +register+, +items+, +applicability+.
    #
    # Item version entries are immutable per version and perfectly
    # cacheable — only register status is mutable — so a FileStore may
    # also serve as an offline mirror of a remote register.
    class FileStore < Store
      class FormatError < Unidpp::Error; end

      ITEM_GLOB = "items/*.{yaml,yml,json}".freeze
      BINDING_GLOB = "bindings/*.{yaml,yml,json}".freeze

      # @param path [String] directory or single document file
      def initialize(path)
        @path = File.expand_path(path)
        @directory = File.directory?(@path)
        freeze_content
      end

      # @return [Array<Item>]
      def items
        content[:items]
      end

      # @return [Array<ApplicabilityBinding>]
      def bindings
        content[:bindings]
      end

      # @return [Register, nil]
      def register
        content[:register]
      end

      private

      def content
        @content
      end

      def freeze_content
        @content =
          if @directory
            load_directory
          else
            load_single_file
          end
      end

      def load_directory
        {
          register: load_register,
          items: Dir[File.join(@path, ITEM_GLOB)].sort.map { |f| load_item(f) },
          bindings: Dir[File.join(@path, BINDING_GLOB)].sort.flat_map { |f| load_bindings(f) },
        }
      end

      def load_single_file
        doc = read_document(@path)
        unless doc.is_a?(Hash)
          raise FormatError, "registry document must be a mapping: #{@path}"
        end

        {
          register: doc["register"] && Register.from_hash(doc["register"]),
          items: Array(doc["items"]).map { |i| Item.from_hash(i) },
          bindings: Array(doc["applicability"] || doc["bindings"])
                      .map { |b| ApplicabilityBinding.from_hash(b) },
        }
      end

      def load_register
        path = Dir[File.join(@path, "register.{yaml,yml,json}")].first
        doc = path && read_document(path)
        doc && Register.from_hash(doc)
      end

      def load_item(path)
        Item.from_hash(read_document(path))
      end

      def load_bindings(path)
        doc = read_document(path)
        list = doc.is_a?(Hash) ? doc["bindings"] : doc
        Array(list).map { |b| ApplicabilityBinding.from_hash(b) }
      end

      # Reads a raw JSON or YAML document (plain data; YAML timestamps are
      # permitted and cast to ISO strings by the lutaml DateTime type).
      def read_document(path)
        if File.extname(path) == ".json"
          JSON.parse(File.read(path))
        else
          YAML.safe_load(File.read(path),
                         permitted_classes: [Time, Date, DateTime],
                         aliases: true)
        end
      end
    end
  end
end
