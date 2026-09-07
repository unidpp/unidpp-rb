# frozen_string_literal: true

require "spec_helper"

RSpec.describe Unidpp::Registry::ApplicabilityBinding do
  let(:store) do
    Unidpp::Registry::FileStore.new(File.join(FIXTURES, "registry"))
  end
  let(:client) { Unidpp::Registry::Client.new(store: store) }
  let(:subject_id) { "gtin:06901234000016" }

  def profiles_at(t)
    client.applicable_profiles(subject_id, as_of: t)
          .map(&:profile_item).sort
  end

  describe "the as-of query: which profiles applied at T" do
    it "returns the EU, minerals and retroactive heritage profiles in 2027" do
      expect(profiles_at("2027-06-01T00:00:00+00:00"))
        .to eq(["conflict-minerals", "eu-espr-textiles", "historic-vehicle"])
    end

    it "adds the JP profile from its effective date" do
      expect(profiles_at("2029-06-01T00:00:00+00:00"))
        .to eq(["conflict-minerals", "eu-espr-textiles", "historic-vehicle",
                "jp-meti-electronics"])
    end

    it "does not reach before a binding's effective_from" do
      expect(profiles_at("2019-01-01T00:00:00+00:00"))
        .to eq(["historic-vehicle"])
    end
  end

  describe "retroactivity" do
    it "applies a retroactive binding from its effective_from" do
      # historic-vehicle: effective 1996-01-01, registered 2026-05-01,
      # retroactive — legally backdated.
      expect(profiles_at("2010-01-01T00:00:00+00:00"))
        .to include("historic-vehicle")
    end

    it "does not apply a non-retroactive binding before registered_at" do
      # conflict-minerals: effective 2021-01-01, registered 2023-01-01,
      # non-retroactive — no obligations before declaration.
      expect(profiles_at("2022-01-01T00:00:00+00:00"))
        .not_to include("conflict-minerals")
      expect(profiles_at("2024-01-01T00:00:00+00:00"))
        .to include("conflict-minerals")
    end

    it "honours effective_until (withdrawn applicability)" do
      binding = Unidpp::Registry::ApplicabilityBinding.new(
        subject: subject_id, profile_item: "x",
        effective_from: "2020-01-01T00:00:00+00:00",
        effective_until: "2025-01-01T00:00:00+00:00",
        registered_at: "2020-01-01T00:00:00+00:00"
      )
      expect(binding.applies_at?("2024-12-31T23:59:59+00:00")).to be true
      expect(binding.applies_at?("2025-06-01T00:00:00+00:00")).to be false
    end
  end

  describe "joining bindings to version-pinned profiles" do
    it "resolves the applicable profile items at T" do
      items = client.applicable_profile_items(subject_id,
                                               as_of: "2027-06-01T00:00:00+00:00")
      expect(items.map(&:identifier))
        .to contain_exactly("eu-espr-textiles", "conflict-minerals",
                            "historic-vehicle")
      expect(items).to all(be_profile)
    end

    it "yields the applicable manifests at T" do
      manifests = client.applicable_manifests(subject_id,
                                               as_of: "2029-06-01T00:00:00+00:00")
      ids = manifests.map(&:profile_id)
      expect(ids).to contain_exactly("eu-espr-textiles", "jp-meti-electronics",
                                     "conflict-minerals", "historic-vehicle")
      jp = manifests.find { |m| m.profile_id == "jp-meti-electronics" }
      expect(jp.jurisdiction_profile?).to be true
      expect(jp.capability_class).to eq("S2")
    end
  end

  describe "profile growth is dated binding, not new identity" do
    it "reconstructs manifest history: the profile set at each instant" do
      # 2027: EU (from 2026-10), minerals (declared 2023), heritage
      # (retroactive to 1996) — JP not yet applicable.
      expect(profiles_at("2027-01-01T00:00:00+00:00"))
        .to eq(["conflict-minerals", "eu-espr-textiles", "historic-vehicle"])
    end

    it "round-trips bindings through lutaml-model mappings" do
      binding = client.bindings_for(subject_id)
                      .find { |b| b.profile_item == "historic-vehicle" }
      round = described_class.from_yaml(binding.to_yaml)
      expect(round).to eq(binding)
      expect(round).to be_retroactive
    end
  end
end
