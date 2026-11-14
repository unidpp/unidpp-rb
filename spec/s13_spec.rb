# frozen_string_literal: true

# The S13 trust layer's gates (XB-6/7): the F2 signed-exchange vector
# verifies through the graph projection (and fails on tampering), the
# countersigned vector verifies at its sequence and fails on a stale
# one, and the choreography journal replays from the envelopes alone
# — refusing an answer bound to no journaled request.

require "spec_helper"
require "json"

RSpec.describe Unidpp::S13 do
  def vectors(name)
    JSON.parse(File.read(File.expand_path("fixtures/vectors/#{name}", __dir__)))
  end

  def graph(doc, roles)
    roles.to_h do |node, field|
      public_hex = doc[field]
      [node, { Unidpp::S13.key_id("ed25519", [public_hex].pack("H*")) => [public_hex].pack("H*") }]
    end
  end

  describe "the envelope verify" do
    let(:exchange) { vectors("s13-signed-exchange.json") }

    it "the F2 signed exchange verifies under its publics" do
      graph = graph(exchange, "de-zoll" => "requester_public_hex",
                             "weilian-shenzhen" => "responder_public_hex")
      expect(Unidpp::S13.verify_request(exchange["signed_request"], graph)).to eq(ok: true)
      expect(Unidpp::S13.verify_response(exchange["signed_response"], graph)).to eq(ok: true)
    end

    it "a tampered subject fails the requester's slot" do
      graph = graph(exchange, "de-zoll" => "requester_public_hex")
      signed = JSON.parse(JSON.dump(exchange["signed_request"]))
      signed["request"]["subject"] = "urn:unidpp:passport:other"
      verdict = Unidpp::S13.verify_request(signed, graph)
      expect(verdict[:ok]).to be(false)
      expect(verdict[:why]).to include("does not verify")
    end

    it "an unanchored node refuses before any crypto" do
      verdict = Unidpp::S13.verify_request(exchange["signed_request"], {})
      expect(verdict[:ok]).to be(false)
      expect(verdict[:why]).to include("no such keys")
    end
  end

  describe "the non-repudiable answer (XB-7)" do
    let(:doc) { vectors("s13-countersigned.json") }
    let(:countersigned) { doc["countersigned"] }

    it "verifies at its sequence under the authority's key" do
      graph = graph(doc, "de-zoll" => "requester_public_hex",
                          "weilian-shenzhen" => "responder_public_hex",
                          "cn-samr" => "authority_public_hex")
      expect(Unidpp::S13.verify_non_repudiable(countersigned, graph, 1)).to eq(ok: true)
    end

    it "a stale expected sequence refuses (a replayed answer)" do
      graph = graph(doc, "weilian-shenzhen" => "responder_public_hex",
                          "cn-samr" => "authority_public_hex")
      verdict = Unidpp::S13.verify_non_repudiable(countersigned, graph, 2)
      expect(verdict[:ok]).to be(false)
      expect(verdict[:why]).to include("stale sequence 1 (expected 2)")
    end
  end

  describe "the choreography journal replay (XB-6)" do
    let(:exchange) { vectors("s13-signed-exchange.json") }
    let(:doc) { vectors("s13-countersigned.json") }

    def journal
      {
        "side" => "custodian",
        "entries" => [
          exchange["signed_request"],
          exchange["signed_response"],
          doc["countersigned"]
        ]
      }
    end

    def full_graph
      graph(doc, "de-zoll" => "requester_public_hex",
                  "weilian-shenzhen" => "responder_public_hex",
                  "cn-samr" => "authority_public_hex")
    end

    it "replays to the decisions in journal sequence" do
      replayed = Unidpp::S13.replay(journal, full_graph)
      expect(replayed[:ok]).to be(true)
      expect(replayed[:decisions].size).to eq(2)
      expect(replayed[:decisions].all? { |d| d[:outcome] == "attestation-offer" }).to be(true)
      expect(replayed[:decisions].all? { |d| d[:governing_policy] == "cn-dynamic-bms" }).to be(true)
    end

    it "an answer bound to no journaled request refuses" do
      orphan = { "side" => "custodian", "entries" => [exchange["signed_response"]] }
      replayed = Unidpp::S13.replay(orphan, full_graph)
      expect(replayed[:ok]).to be(false)
      expect(replayed[:why]).to include("bound to no journaled request")
    end
  end
end
