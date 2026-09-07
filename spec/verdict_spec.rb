# frozen_string_literal: true

require "spec_helper"

RSpec.describe Unidpp::Verdict do
  describe "the three verification readings" do
    it "carries the reading vocabulary" do
      expect(described_class::READINGS)
        .to eq(%w[evidentiary current_state cryptographic])
    end

    it "answers which reading it gives" do
      expect(described_class.new(reading: "evidentiary")).to be_evidentiary
      expect(described_class.new(reading: "current_state")).to be_current_state
      expect(described_class.new(reading: "cryptographic")).to be_cryptographic
    end

    it "rejects an unknown reading" do
      expect(described_class.new(reading: "gut-feeling").validate)
        .not_to be_empty
    end
  end

  describe "freshness degradation is explicit" do
    it "carries the freshness vocabulary" do
      expect(described_class::FRESHNESS)
        .to eq(%w[fresh stale offline_degraded unavailable])
    end

    it "marks anything not fresh as degraded" do
      expect(described_class.new(reading: "cryptographic", freshness: "fresh"))
        .not_to be_degraded
      %w[stale offline_degraded unavailable].each do |state|
        expect(described_class.new(reading: "cryptographic", freshness: state))
          .to be_degraded
      end
    end

    it "rejects an unknown freshness class" do
      expect(described_class.new(reading: "evidentiary",
                                 freshness: "mostly-fine").validate)
        .not_to be_empty
    end
  end

  describe "coverage reports" do
    let(:verdict) do
      described_class.new(
        reading: "evidentiary", freshness: "offline_degraded",
        rendered_at: "2027-05-01T00:00:00+00:00",
        covered: %w[urn:dp:a urn:dp:b], missing: %w[urn:dp:c]
      )
    end

    it "computes coverage" do
      expect(verdict.coverage_ratio).to eq(Rational(2, 3))
      expect(verdict).not_to be_complete
      expect(verdict).to be_degraded
    end

    it "is complete when nothing is missing" do
      verdict.missing = []
      expect(verdict).to be_complete
      expect(verdict.coverage_ratio).to eq(Rational(1))
    end

    it "round-trips YAML and JSON" do
      expect(described_class.from_yaml(verdict.to_yaml)).to eq(verdict)
      expect(described_class.from_json(verdict.to_json)).to eq(verdict)
    end
  end
end
