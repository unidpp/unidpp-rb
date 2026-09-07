# frozen_string_literal: true

require "spec_helper"

RSpec.describe Unidpp::Quantity do
  let(:kwh) { "https://unitsml.org/unit#kWh" }
  let(:mj) { "https://unitsml.org/unit#MJ" }

  describe "value + registered unit URI" do
    it "carries value and unit" do
      q = described_class.new(value: BigDecimal("10.5"), unit: kwh)
      expect(q.value).to eq(BigDecimal("10.5"))
      expect(q.unit).to eq(kwh)
      expect(q.uncertainty).to be_nil
    end

    it "carries standard uncertainty with coverage factor" do
      u = described_class::Uncertainty.new(value: BigDecimal("0.2"))
      expect(u.coverage_factor).to eq(BigDecimal(2))
      expect(u.expanded).to eq(BigDecimal("0.4"))
    end
  end

  describe "strict-unit arithmetic (no implicit conversion)" do
    it "adds and subtracts same-unit quantities" do
      a = described_class.new(value: BigDecimal("10.5"), unit: kwh)
      b = described_class.new(value: BigDecimal("9.5"), unit: kwh)
      expect((a + b).value).to eq(BigDecimal(20))
      expect((a - b).value).to eq(BigDecimal(1))
    end

    it "raises on unit mismatch — convert through registered transforms" do
      a = described_class.new(value: BigDecimal("10.5"), unit: kwh)
      b = described_class.new(value: BigDecimal("37.8"), unit: mj)
      expect { a + b }
        .to raise_error(Unidpp::Quantity::UnitMismatchError, /registered transform/)
      expect { a - b }.to raise_error(Unidpp::Quantity::UnitMismatchError)
    end

    it "scales by a scalar factor, unit unchanged" do
      a = described_class.new(value: BigDecimal("2"), unit: kwh)
      expect((a * 3).value).to eq(BigDecimal(6))
      expect((a * 3).unit).to eq(kwh)
    end

    it "propagates combined standard uncertainty" do
      a = described_class.new(value: BigDecimal("10"), unit: kwh,
                             uncertainty: described_class::Uncertainty.new(
                               value: BigDecimal("3")
                             ))
      b = described_class.new(value: BigDecimal("10"), unit: kwh,
                             uncertainty: described_class::Uncertainty.new(
                               value: BigDecimal("4")
                             ))
      sum = a + b
      expect(sum.uncertainty.value).to eq(BigDecimal(5)) # sqrt(9+16)
    end
  end

  describe "conformity decision rules (ILAC-G8 shared risk)" do
    let(:measured) do
      described_class.new(
        value: BigDecimal("100.0"), unit: kwh,
        uncertainty: described_class::Uncertainty.new(value: BigDecimal("0.5"))
      )
    end

    it "agrees within expanded combined uncertainty" do
      other = described_class.new(
        value: BigDecimal("101.5"), unit: kwh,
        uncertainty: described_class::Uncertainty.new(value: BigDecimal("0.5"))
      )
      # |delta| = 1.5 <= 2 * sqrt(0.25 + 0.25) ~ 1.414? -> false; boundary test
      expect(measured.agrees_with?(other)).to be false
      closer = described_class.new(
        value: BigDecimal("101.4"), unit: kwh,
        uncertainty: described_class::Uncertainty.new(value: BigDecimal("0.5"))
      )
      expect(measured.agrees_with?(closer)).to be true
    end

    it "requires exact equality when uncertainty is absent" do
      exact = described_class.new(value: BigDecimal("100.0"), unit: kwh)
      other = described_class.new(value: BigDecimal("100.0"), unit: kwh)
      off = described_class.new(value: BigDecimal("100.1"), unit: kwh)
      expect(exact.agrees_with?(other)).to be true
      expect(exact.agrees_with?(off)).to be false
    end
  end

  describe "mass-balance conservation over same-unit ledgers" do
    it "conserves in - out = loss exactly (no float drift)" do
      inputs = [described_class.new(value: BigDecimal("500"), unit: kwh),
                described_class.new(value: BigDecimal("250.5"), unit: kwh)]
      outputs = [described_class.new(value: BigDecimal("650.25"), unit: kwh)]
      in_total = inputs.reduce { |acc, q| acc + q }
      out_total = outputs.reduce { |acc, q| acc + q }
      loss = in_total - out_total
      expect(loss.value).to eq(BigDecimal("100.25"))
      expect(loss.negative?).to be false
    end
  end

  describe "round-trips (lutaml-model mappings)" do
    it "round-trips YAML" do
      q = described_class.new(
        value: BigDecimal("10.5"), unit: kwh,
        uncertainty: described_class::Uncertainty.new(value: BigDecimal("0.2"))
      )
      expect(described_class.from_yaml(q.to_yaml)).to eq(q)
    end

    it "round-trips JSON (decimal survives in normalized form)" do
      q = described_class.new(value: BigDecimal("10.5"), unit: kwh)
      round = described_class.from_json(q.to_json)
      expect(round).to eq(q)
      expect(round.value).to eq(BigDecimal("10.5"))
    end
  end
end
