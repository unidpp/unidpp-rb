# frozen_string_literal: true

require "spec_helper"

RSpec.describe Unidpp::Registry::Client do
  let(:store) do
    Unidpp::Registry::FileStore.new(File.join(FIXTURES, "registry"))
  end
  let(:client) { described_class.new(store: store) }

  describe "the file store adapter" do
    it "loads register metadata with the 19135 governance roles" do
      expect(client.register.register_id).to eq("unidpp-dev")
      expect(client.register.register_owner).to eq("UniDPP (multi-body stewardship)")
      expect(client.register.control_body).to eq("ISO/TC 154 liaison")
    end

    it "loads one item per file" do
      expect(client.items.map(&:identifier))
        .to contain_exactly("eu-espr-textiles", "jp-meti-electronics",
                            "historic-vehicle", "conflict-minerals",
                            "unit-kwh", "legacy-data-element")
    end

    it "loads applicability bindings" do
      expect(client.bindings_for("gtin:06901234000016").size).to eq(4)
    end

    it "also loads a single consolidated JSON document" do
      single = Unidpp::Registry::FileStore.new(
        File.join(FIXTURES, "registry-single.json")
      )
      c2 = described_class.new(store: single)
      expect(c2.register.register_id).to eq("unidpp-single")
      expect(c2.items.size).to eq(2)
      expect(c2.bindings_for("gtin:06901234000016").size).to eq(1)
    end
  end

  describe "item lookup with version and status" do
    it "finds an item by register and identifier" do
      item = client.item!("eu-espr-textiles", register: "unidpp-dev")
      expect(item.title).to eq("EU ESPR textiles jurisdiction profile")
      expect(item.submitting_organization).to eq("CEN-CLC/JTC 24")
    end

    it "scopes lookup by register" do
      expect(client.item("eu-espr-textiles", register: "other-register"))
        .to be_nil
    end

    it "raises a typed error for unknown items" do
      expect { client.item!("no-such-item") }
        .to raise_error(Unidpp::Registry::Client::ItemNotFoundError)
    end

    it "returns the pinned version when given, current otherwise" do
      expect(client.version_of("eu-espr-textiles", version: "0.9.0").status)
        .to eq("superseded")
      expect(client.version_of("eu-espr-textiles").status).to eq("valid")
    end

    it "raises when no version is in force" do
      expect { client.version_of("legacy-data-element") }
        .to raise_error(Unidpp::Registry::Client::NoValidVersionError)
    end
  end

  describe "supersession chains" do
    it "follows supersession links to the terminal version" do
      item = client.item!("eu-espr-textiles")
      expect(item.supersession_chain.map(&:version)).to eq(%w[0.9.0 1.0.0])
      expect(item.supersession_chain.map(&:status))
        .to eq(%w[superseded valid])
    end

    it "resolves to the current valid version" do
      expect(client.resolve("eu-espr-textiles").version).to eq("1.0.0")
    end

    it "starts a chain from any version" do
      chain = client.supersession_chain("historic-vehicle", from: "1.0.0")
      expect(chain.map(&:version)).to eq(%w[1.0.0 2.0.0])
    end

    it "raises for a broken supersession link" do
      item = client.item!("historic-vehicle")
      item.versions.first.superseded_by_version = "9.9.9"
      expect { item.supersession_chain }
        .to raise_error(Unidpp::Registry::Item::UnknownVersionError)
    end
  end

  describe "point-in-time registry state" do
    it "returns the version in force at T" do
      expect(client.version_as_of("eu-espr-textiles",
                                  as_of: "2027-06-01T00:00:00+00:00").version)
        .to eq("0.9.0")
      expect(client.version_as_of("eu-espr-textiles",
                                  as_of: "2028-01-01T00:00:00+00:00").version)
        .to eq("1.0.0")
    end

    it "derives the window end from the successor when no explicit until" do
      # historic-vehicle 1.0.0 has no effective_until; its window closes
      # when 2.0.0 becomes effective (2021-06-01).
      expect(client.version_as_of("historic-vehicle",
                                  as_of: "2010-01-01T00:00:00+00:00").version)
        .to eq("1.0.0")
      expect(client.version_as_of("historic-vehicle",
                                  as_of: "2022-01-01T00:00:00+00:00").version)
        .to eq("2.0.0")
    end

    it "returns nil before the item existed" do
      expect(client.version_as_of("eu-espr-textiles",
                                  as_of: "2020-01-01T00:00:00+00:00"))
        .to be_nil
    end
  end

  describe "profile items and version pinning (seam S4)" do
    it "embeds the manifest and pins it to a registered version" do
      item = client.item!("eu-espr-textiles")
      expect(item.profile?).to be true
      expect(item.manifest.profile_id).to eq("eu-espr-textiles")
      expect(item).to be_manifest_version_pinned
      expect(item.manifest.legal_basis)
        .to eq("https://eur-lex.europa.eu/eli/reg/2024/1781/oj")
    end

    it "flags an unpinned manifest" do
      item = client.item!("eu-espr-textiles")
      item.manifest.version = "99.0.0"
      expect(item).not_to be_manifest_version_pinned
    end
  end

  describe "registry round-trips (lutaml-model mappings)" do
    it "round-trips an item through YAML" do
      item = client.item!("eu-espr-textiles")
      round = Unidpp::Registry::Item.from_yaml(item.to_yaml)
      expect(round).to eq(item)
      expect(round.manifest).to eq(item.manifest)
    end

    it "round-trips an item through JSON" do
      item = client.item!("historic-vehicle")
      round = Unidpp::Registry::Item.from_json(item.to_json)
      expect(round).to eq(item)
      expect(round.manifest.triggers.first.subject).to eq("object.age_years")
    end
  end
end
