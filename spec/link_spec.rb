# frozen_string_literal: true

require "spec_helper"

RSpec.describe Unidpp::PassportLink do
  let(:battery) do
    Unidpp::ProductIdentifier.parse(
      "https://id.example.com/01/09506000134352/21/BAT-77"
    )
  end
  let(:car) do
    Unidpp::ProductIdentifier.parse(
      "https://id.example.com/01/06901234000016/21/CAR-1"
    )
  end

  describe "installation binding attributes" do
    subject(:link) do
      described_class.new(
        link_type: "installation",
        child: battery,
        parent: car,
        binding_method: "soldered",
        slot_id: "battery-slot-1",
        pairing: "firmware",
        alterations: ["conformal coating", "potted connectors"],
        recoverability: "harvestable",
        interval: Unidpp::LinkInterval.new(
          from: "2027-03-01T10:00:00+00:00"
        )
      )
    end

    it "carries method, slot, pairing, alteration and recoverability" do
      expect(link.installation?).to be true
      expect(link.binding_method).to eq("soldered")
      expect(link.slot_id).to eq("battery-slot-1")
      expect(link.pairing).to eq("firmware")
      expect(link.alterations).to eq(["conformal coating", "potted connectors"])
      expect(link.recoverability).to eq("harvestable")
    end

    it "keeps identity continuity only for restorable/harvestable" do
      expect(link.identity_continuity?).to be true
      link.recoverability = "destructive"
      expect(link.identity_continuity?).to be false
    end

    it "carries a temporal interval" do
      expect(link.interval.covers?("2028-01-01T00:00:00+00:00")).to be true
      expect(link.interval.covers?("2026-01-01T00:00:00+00:00")).to be false
    end

    it "round-trips YAML with the nested identifiers" do
      round = described_class.from_yaml(link.to_yaml)
      expect(round).to eq(link)
      expect(round.child.canonical).to eq(battery.canonical)
      expect(round.parent.canonical).to eq(car.canonical)
    end

    it "round-trips JSON" do
      expect(described_class.from_json(link.to_json)).to eq(link)
    end

    it "is valid against the edge vocabularies" do
      expect(link.validate).to be_empty
    end
  end

  describe "visibility classes" do
    it "defaults to a public edge" do
      link = described_class.new(link_type: "association",
                                 child: battery, parent: car)
      expect(link.visibility).to eq("public")
      expect(link.blind?).to be false
    end

    it "flags an unknown visibility class" do
      link = described_class.new(link_type: "custody",
                                 child: battery, parent: car,
                                 visibility: "invisible")
      expect(link.validate).not_to be_empty
    end

    it "supports escrowed disclosure" do
      link = described_class.new(link_type: "installation",
                                 child: battery, parent: car,
                                 visibility: "escrowed", escrow: "trustee",
                                 audiences: ["regulator", "insurer"])
      expect(link.escrowed?).to be true
      expect(link.escrow).to eq("trustee")
      expect(link.audiences).to eq(%w[regulator insurer])
    end
  end

  describe "blind edges: proof-of-binding without knowledge-of-parent" do
    subject(:link) do
      described_class.install(
        child: battery, parent: car, visibility: "blind",
        salt: "a1b2c3d4e5f60718", binding_method: "fastened",
        slot_id: "battery-slot-1", recoverability: "harvestable"
      )
    end

    it "hides the parent while proving the binding" do
      expect(link.blind?).to be true
      expect(link.hidden_parent?).to be true
      expect(link.parent).to be_nil
      expect(link.parent_commitment).to match(/\A[0-9a-f]{64}\z/)
    end

    it "proves the true parent without revealing it" do
      expect(link.proves_parent?(car)).to be true
    end

    it "refutes a different candidate parent" do
      other = Unidpp::ProductIdentifier.parse(
        "https://id.example.com/01/06901234000016/21/CAR-2"
      )
      expect(link.proves_parent?(other)).to be false
      expect(link.proves_parent?(nil)).to be false
    end

    it "round-trips the commitment intact (salt = disclosure key)" do
      round = described_class.from_yaml(link.to_yaml)
      expect(round.parent_commitment).to eq(link.parent_commitment)
      expect(round.commitment_salt).to eq("a1b2c3d4e5f60718")
      expect(round.proves_parent?(car)).to be true
      expect(round).to eq(link)
    end

    it "binds to the child identity too (not just the parent)" do
      other_child = Unidpp::ProductIdentifier.parse(
        "https://id.example.com/01/09506000134352/21/BAT-99"
      )
      forged = described_class.new(
        link_type: "installation", child: other_child,
        visibility: "blind", parent_commitment: link.parent_commitment,
        commitment_salt: link.commitment_salt
      )
      expect(forged.proves_parent?(car)).to be false
    end
  end

  describe "visible installation edges" do
    it "keeps the parent and proves by identity" do
      link = described_class.install(child: battery, parent: car,
                                     visibility: "public")
      expect(link.parent).to eq(car)
      expect(link.proves_parent?(car)).to be true
    end
  end

  describe "edge types" do
    it "rejects an unknown edge type" do
      link = described_class.new(link_type: "contains", child: battery)
      expect(link.validate).not_to be_empty
    end

    it "carries the full R1-R7 vocabulary" do
      expect(described_class::TYPES).to eq(
        %w[association derivation installation type-lineage profile-of
           custody membership]
      )
    end
  end
end
