# frozen_string_literal: true

require "spec_helper"

RSpec.describe Unidpp::ProductIdentifier do
  describe "GS1 Digital Link with AI 01/10/21" do
    subject(:id) do
      described_class.parse(
        "https://id.example.com/01/09506000134352/10/ABC-123/21/9876543"
      )
    end

    it "recognizes the scheme and normalizes the GS1 keys" do
      expect(id.scheme).to eq("gs1-dl")
      expect(id.gtin).to eq("09506000134352")
      expect(id.lot).to eq("ABC-123")
      expect(id.serial).to eq("9876543")
    end

    it "derives item granularity from the serial (AI 21)" do
      expect(id.granularity).to eq("item")
      expect(id.item?).to be true
    end

    it "validates the GTIN check digit" do
      expect(id.valid_keys?).to be true
    end

    it "canonicalizes to the element-string form" do
      expect(id.canonical)
        .to eq("(01)09506000134352(10)ABC-123(21)9876543")
    end

    it "rejects a bad GTIN check digit" do
      expect do
        described_class.parse("https://id.example.com/01/09506000134353/10/L")
      end.to raise_error(Unidpp::Error, /check digit/)
    end
  end

  describe "granularity ladder" do
    it "GTIN only is model level" do
      id = described_class.parse("https://id.example.com/01/09506000134352")
      expect(id.granularity).to eq("model")
      expect(id.model?).to be true
    end

    it "GTIN + lot (AI 10) is batch level" do
      id = described_class.parse(
        "https://id.example.com/01/09506000134352/10/LOT-9"
      )
      expect(id.granularity).to eq("batch")
    end
  end

  describe "GS1 element string" do
    it "parses the parenthesized form identically to the Digital Link" do
      element = described_class.parse(
        "(01)09506000134352(10)ABC-123(21)9876543"
      )
      dl = described_class.parse(
        "https://id.example.com/01/09506000134352/10/ABC-123/21/9876543"
      )
      expect(element.scheme).to eq("gs1-element")
      expect(element.canonical).to eq(dl.canonical)
      expect(element.canonical_id).to eq(dl.canonical_id)
    end

    it "rejects an element string without an identity AI" do
      expect { described_class.parse("(10)ONLY-LOT") }
        .to raise_error(Unidpp::ProductIdentifier::ParseError)
    end
  end

  describe "ISO/IEC 15459-style transport-unit identifier" do
    it "parses a bracketed SSCC element string" do
      id = described_class.parse("[00]006141411234567890")
      expect(id.scheme).to eq("iso-15459")
      expect(id.sscc).to eq("006141411234567890")
      expect(id.granularity).to eq("item")
      expect(id.canonical).to eq("(00)006141411234567890")
      expect(id.valid_keys?).to be true
    end

    it "parses a parenthesized SSCC" do
      id = described_class.parse("(00)106141411234567897")
      expect(id.sscc).to eq("106141411234567897")
      expect(id.valid_keys?).to be true
    end

    it "rejects an SSCC with an invalid check digit" do
      expect { described_class.parse("[00]006141411234567891") }
        .to raise_error(Unidpp::Error, /check digit/)
    end
  end

  describe "GB/T 33993-style national carrier wrapper" do
    subject(:id) do
      described_class.parse("https://gds.example.com/p/06901234000016?lot=L1")
    end

    it "finds the embedded GTIN (690-prefix national number)" do
      expect(id.scheme).to eq("gbt-33993")
      expect(id.gtin).to eq("06901234000016")
      expect(id.lot).to eq("L1")
      expect(id.granularity).to eq("batch")
      expect(id.valid_keys?).to be true
    end

    it "carries the serial as item granularity when present" do
      id = described_class.parse(
        "https://gds.example.com/p/06901234000016?lot=L1&serial=S-7"
      )
      expect(id.serial).to eq("S-7")
      expect(id.item?).to be true
    end

    it "rejects a GTIN segment with a bad check digit" do
      expect { described_class.parse("https://gds.example.com/p/06901234000017") }
        .to raise_error(Unidpp::ProductIdentifier::ParseError)
    end
  end

  describe "URNs" do
    it "parses an EPC sgtin URN and reconstructs the GTIN" do
      id = described_class.parse("urn:epc:id:sgtin:0614141.107346.2017")
      expect(id.scheme).to eq("urn")
      expect(id.gtin).to eq("06141411073468")
      expect(id.serial).to eq("2017")
      expect(id.item?).to be true
      expect(id.valid_keys?).to be true
    end

    it "parses an EPC sscc URN, completing the check digit" do
      id = described_class.parse("urn:epc:id:sscc:0614141.1234567890")
      expect(id.sscc).to eq("061414112345678902")
      expect(id.item?).to be true
    end

    it "keeps a plain URN as a model-level identity" do
      id = described_class.parse("urn:unidpp:type:acme-laptop-x1")
      expect(id.scheme).to eq("urn")
      expect(id.value).to eq("urn:unidpp:type:acme-laptop-x1")
      expect(id.model?).to be true
      expect(id.canonical_id).to eq("urn:unidpp:type:acme-laptop-x1")
    end
  end

  describe "rejections" do
    it "rejects unrecognized syntax" do
      expect { described_class.parse("not-an-identifier") }
        .to raise_error(Unidpp::ProductIdentifier::ParseError)
    end

    it "rejects blank input" do
      expect { described_class.parse("  ") }
        .to raise_error(Unidpp::ProductIdentifier::ParseError)
    end

    it "rejects a URL with no identity content" do
      expect { described_class.parse("https://example.com/shop") }
        .to raise_error(Unidpp::ProductIdentifier::ParseError)
    end
  end

  describe "serialization round-trips (lutaml-model mappings)" do
    let(:id) do
      described_class.parse(
        "https://id.example.com/01/09506000134352/10/ABC-123/21/9876543"
      )
    end

    it "round-trips YAML" do
      expect(described_class.from_yaml(id.to_yaml)).to eq(id)
    end

    it "round-trips JSON" do
      expect(described_class.from_json(id.to_json)).to eq(id)
    end

    it "canonical survives the round-trip" do
      expect(described_class.from_yaml(id.to_yaml).canonical).to eq(id.canonical)
    end
  end
end
