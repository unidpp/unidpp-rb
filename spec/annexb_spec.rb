# frozen_string_literal: true

# The Annex B binary canonical encoding against the vendored golden
# vectors (TODO 237): every fixture's object re-derives the reference
# `canonical_hex` pin byte for byte. An implementation we did not
# write reproduces the reference bytes or this suite fails — the
# cross-implementation contract (CN-1).

require "spec_helper"
require "json"

RSpec.describe Unidpp::AnnexB do
  def self.fixture(name)
    @fixtures ||= {}
    @fixtures[name] ||= JSON.parse(File.read(File.join(vectors_dir, name)))
  end

  def self.vectors_dir
    File.expand_path("fixtures/vectors", __dir__)
  end

  def hex(bytes)
    bytes.unpack1("H*")
  end

  it "reproduces the S13 request" do
    doc = self.class.fixture("request.json")
    expect(hex(described_class.request_canonical(doc["request"]))).to eq(doc["canonical_hex"])
  end

  it "reproduces the S13 response" do
    doc = self.class.fixture("response.json")
    expect(hex(described_class.response_canonical(doc["response"]))).to eq(doc["canonical_hex"])
  end

  it "reproduces the coverage report (with its route digest)" do
    doc = self.class.fixture("coverage-report.json")
    expect(hex(described_class.report_canonical(doc["report"]))).to eq(doc["canonical_hex"])
  end

  it "reproduces the grid policy" do
    doc = self.class.fixture("policy.json")
    expect(hex(described_class.policy_canonical(doc["policy"]))).to eq(doc["canonical_hex"])
  end

  it "reproduces the attestation statement" do
    doc = self.class.fixture("attestation-statement.json")
    expect(hex(described_class.statement_canonical(doc["statement"]))).to eq(doc["canonical_hex"])
  end

  it "reproduces the frozen view (with its spine digest)" do
    doc = self.class.fixture("frozen-view.json")
    expect(hex(described_class.frozen_view_canonical(doc["view"]))).to eq(doc["canonical_hex"])
  end

  it "reproduces the interop declaration" do
    doc = self.class.fixture("interop-declaration.json")
    expect(hex(described_class.declaration_canonical(doc["declaration"]))).to eq(doc["canonical_hex"])
  end

  it "reproduces the mapping correspondence and divergence" do
    doc = self.class.fixture("mapping-chain.json")
    expect(hex(described_class.mapping_item_canonical(doc["correspondence"]))).to eq(doc["correspondence_canonical_hex"])
    expect(hex(described_class.mapping_item_canonical(doc["divergence"]))).to eq(doc["divergence_canonical_hex"])
  end
end
