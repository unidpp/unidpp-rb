# frozen_string_literal: true

# The family's golden vectors, consumed from the vendored corpus
# (TODO 234). Every fixture is the corpus Rust pinned, byte for byte
# (the manifest pins the digests; the e2e harness cross-checks them
# against unidpp-core's originals). This spec holds the Ruby half
# that exists today: the corpus identity and the canonical key order
# being stable over the whole corpus. The Annex B binary canonical
# encoder for Ruby is the named successor (TODO.complete/237).

require "spec_helper"
require "json"
require "digest"

RSpec.describe "the vendored golden vectors" do
  def self.vectors_dir
    File.expand_path("fixtures/vectors", __dir__)
  end

  it "carries the corpus the manifest pins" do
    File.read(File.join(self.class.vectors_dir, "vectors.sha256")).each_line do |line|
      digest, name = line.strip.split(/\s+/)
      expect(Digest::SHA256.file(File.join(self.class.vectors_dir, name)).hexdigest).to eq(digest)
    end
  end

  Dir[File.join(vectors_dir, "*.json")].each do |path|
    it "canonicalizes #{File.basename(path)} stably" do
      doc = JSON.parse(File.read(path))
      once = Unidpp::CanonicalJson.send(:sorted, doc).to_json
      twice = Unidpp::CanonicalJson.send(:sorted, JSON.parse(once)).to_json
      expect(twice).to eq(once)
    end
  end
end
