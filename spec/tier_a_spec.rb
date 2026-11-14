# frozen_string_literal: true

# The Tier-A carrier gates: the corpus carrier decodes to exactly the
# fixture's fields, the round trip re-encodes byte-identically, the
# signing body reconstructs as the carrier's prefix (the empty count
# block's byte aside), and the corpus carrier's ECDSA slot VERIFIES
# under the fixture's anchor through the stdlib OpenSSL binding —
# with a tampered economic-operator field failing loudly.

require "spec_helper"
require "json"

RSpec.describe Unidpp::TierA do
  def fixture
    JSON.parse(File.read(File.expand_path("fixtures/vectors/pack.json", __dir__)))
  end

  def decoded
    doc = fixture
    payload = Unidpp::TierA.decode_hex(doc["hex"])
    expect(payload[:product_id]).to eq(doc["decoded"]["product_id"])
    expect(payload[:resolver_uri]).to eq(doc["decoded"]["resolver_uri"])
    expect(payload[:passport_id]).to eq(doc["decoded"]["passport_id"])
    expect(payload[:eo_id]).to eq(doc["decoded"]["eo_id"])
    expect(payload[:status]).to eq(doc["decoded"]["status"])
    expect(payload[:safety]).to eq(doc["decoded"]["safety"])
    expect(payload[:validity]).to eq(from: doc["decoded"]["validity"]["from"], to: doc["decoded"]["validity"]["to"])
    expect(payload[:as_of]).to eq(doc["decoded"]["as_of"])
    expect(payload[:log_head]).to eq(doc["decoded"]["log_head"])
    doc["decoded"]["signatures"].each_with_index do |want, i|
      expect(payload[:signatures][i][:suite]).to eq(want["suite"])
      expect(payload[:signatures][i][:key_id]).to eq(want["key_id"])
      expect(payload[:signatures][i][:signature].unpack1("H*")).to eq(want["signature_hex"])
    end
    payload
  end

  it "the corpus carrier decodes to the fixture's fields" do
    decoded
  end

  it "the round trip re-encodes byte-identically" do
    doc = fixture
    expect(Unidpp::TierA.encode(decoded)).to eq([doc["hex"]].pack("H*"))
  end

  it "the signing body is the carrier's prefix minus the count byte" do
    doc = fixture
    carrier = [doc["hex"]].pack("H*")
    payload = decoded
    body = Unidpp::TierA.signing_body(payload)
    expect(body).to eq(Unidpp::TierA.encode(payload.merge(signatures: [])))
    expect(carrier.start_with?(body[0...-1])).to be(true)
    expect(carrier.getbyte(body.length - 2)).to eq(0x0B)
    expect(carrier.getbyte(body.length - 1)).to eq(payload[:signatures].length)
  end

  it "the corpus carrier's ECDSA slot verifies under the fixture's anchor" do
    doc = fixture
    payload = decoded
    verdict = Unidpp::TierA.verify(
      payload,
      anchors: { doc["anchor"]["key_id"] => doc["anchor"]["public"] },
      now: payload[:validity][:from],
    )
    expect(verdict[:outcome]).to eq("pass")
    expect(verdict[:achieved_marker]).to eq("third-party-attested")
    expect(verdict[:coverage][:signatures][:verified]).to eq(1)
  end

  it "a tampered economic-operator field fails loudly" do
    doc = fixture
    payload = decoded
    tampered = payload.merge(eo_id: "urn:docs:actor:impostor")
    verdict = Unidpp::TierA.verify(
      tampered,
      anchors: { doc["anchor"]["key_id"] => doc["anchor"]["public"] },
      now: payload[:validity][:from],
    )
    expect(verdict[:outcome]).to eq("fail")
    expect(verdict[:coverage][:signatures][:failed]).to eq(1)
  end
end
