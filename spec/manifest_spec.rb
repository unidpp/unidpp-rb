# frozen_string_literal: true

require "spec_helper"

RSpec.describe Unidpp::ProfileManifest do
  let(:manifest) do
    described_class.new(
      profile_id: "eu-espr-textiles",
      version: "1.0.0",
      register: "unidpp-dev",
      owner: "European Commission",
      legal_basis: "https://eur-lex.europa.eu/eli/reg/2024/1781/oj",
      axes: Unidpp::ProfileAxes.new(
        jurisdictions: ["EU"],
        sectors: ["textiles"],
        characteristics: []
      ),
      triggers: [
        Unidpp::TriggerPredicate.new(
          subject: "object.age_years", operator: "gte", value: "100",
          cites: "urn:unidpp-dev:clause:cites-ivory"
        )
      ],
      capability_class: "S1",
      crypto_suites: [
        Unidpp::CryptoSuiteBinding.new(
          suite_id: "ec-dsa-p-256-sha-256", jurisdiction: "EU",
          use: "sign", phase: "primary"
        ),
        Unidpp::CryptoSuiteBinding.new(
          suite_id: "sm2-sm3", jurisdiction: "CN",
          use: "sign", phase: "composite"
        )
      ],
      data_points: [
        "urn:unidpp-dev:dp:recycled-content-share",
        "urn:unidpp-dev:dp:fibre-composition"
      ],
      languages: %w[en fr de],
      effective_from: "2027-10-18T00:00:00+00:00"
    )
  end

  describe "axes" do
    it "classifies by axis" do
      expect(manifest.jurisdiction_profile?).to be true
      expect(manifest.characteristic_profile?).to be false
    end

    it "supports three-axial composition" do
      axes = Unidpp::ProfileAxes.new(
        jurisdictions: ["EU"], sectors: ["electronics"],
        characteristics: ["conflict_minerals"]
      )
      expect(axes.jurisdictions).to eq(["EU"])
      expect(axes.sectors).to eq(["electronics"])
      expect(axes.characteristics).to eq(["conflict_minerals"])
      expect(axes).not_to be_empty
    end
  end

  describe "trigger predicates" do
    it "applies when every predicate matches (conjunction)" do
      expect(manifest.applies_to?({ "object" => { "age_years" => 120 } }))
        .to be true
      expect(manifest.applies_to?({ "object" => { "age_years" => 5 } }))
        .to be false
    end

    it "does not apply when the fact is missing" do
      expect(manifest.applies_to?({})).to be false
    end

    it "supports exists and contains operators over array facts" do
      predicate = Unidpp::TriggerPredicate.new(
        subject: "materials.origin", operator: "contains", value: "3TG"
      )
      facts = { "materials" => [{ "origin" => "3TG" }, { "origin" => "EU" }] }
      expect(predicate.matches?(facts)).to be true
      expect(predicate.matches?({ "materials" => [{ "origin" => "EU" }] }))
        .to be false
    end

    it "supports time predicates on instants" do
      predicate = Unidpp::TriggerPredicate.new(
        subject: "object.first_registered_at", operator: "before",
        value: "1990-01-01T00:00:00+00:00"
      )
      expect(predicate.matches?(
               { "object" => { "first_registered_at" => "1985-05-05T00:00:00+00:00" } }
             )).to be true
      expect(predicate.time_fired?).to be true
    end

    it "marks age predicates as clock-fired applicability events" do
      predicate = manifest.triggers.first
      expect(predicate.time_fired?).to be true
      expect(manifest.time_triggered?).to be true
    end
  end

  describe "capability classes S0-S3" do
    it "requires the minimum class and accepts better" do
      expect(manifest.satisfiable_for?("S1")).to be true
      expect(manifest.satisfiable_for?("S3")).to be true
      expect(manifest.satisfiable_for?("S0")).to be false
    end

    it "orders the ladder" do
      expect(Unidpp::CapabilityClass.satisfies?("S0", "S3")).to be true
      expect(Unidpp::CapabilityClass.satisfies?("S3", "S0")).to be false
      expect(Unidpp::CapabilityClass.satisfies?("S2", "S2")).to be true
    end
  end

  describe "crypto-suite bindings" do
    it "carries per-jurisdiction suites with migration phases" do
      expect(manifest.crypto_suites.size).to eq(2)
      sm = manifest.crypto_suites.last
      expect(sm.jurisdiction).to eq("CN")
      expect(sm.use).to eq("sign")
      expect(sm.phase).to eq("composite")
      expect(sm.post_quantum?).to be false
    end
  end

  describe "effective window" do
    it "is effective after effective_from" do
      expect(manifest.effective_at?("2028-01-01T00:00:00+00:00")).to be true
      expect(manifest.effective_at?("2027-01-01T00:00:00+00:00")).to be false
    end

    it "honours effective_until" do
      manifest.effective_until = "2030-01-01T00:00:00+00:00"
      expect(manifest.effective_at?("2031-01-01T00:00:00+00:00")).to be false
    end
  end

  describe "round-trips (lutaml-model mappings)" do
    it "round-trips YAML" do
      expect(described_class.from_yaml(manifest.to_yaml)).to eq(manifest)
    end

    it "round-trips JSON" do
      expect(described_class.from_json(manifest.to_json)).to eq(manifest)
    end

    it "round-trips YAML through JSON" do
      from_yaml = described_class.from_yaml(manifest.to_yaml)
      expect(described_class.from_json(from_yaml.to_json)).to eq(manifest)
    end

    it "keeps the manifest valid against the vocabularies" do
      expect(manifest.validate).to be_empty
    end
  end

  describe "vocabulary enforcement" do
    it "flags an unknown capability class" do
      bad = described_class.new(profile_id: "x", capability_class: "S9")
      expect(bad.validate).not_to be_empty
    end

    it "flags an unknown resolution scope" do
      bad = described_class.new(profile_id: "x", resolution: "galactic")
      expect(bad.validate).not_to be_empty
    end

    it "flags an unknown predicate operator" do
      bad = Unidpp::TriggerPredicate.new(subject: "a", operator: "near")
      expect(bad.validate).not_to be_empty
    end
  end
end
