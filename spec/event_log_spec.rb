# frozen_string_literal: true

require "spec_helper"

RSpec.describe Unidpp::EventLog do
  let(:subject_id) { "gtin:06901234000016/ser:CAR-1" }

  def event(type, at:, role: "custodian", payload: {}, trust: "unsigned")
    Unidpp::Event.new(
      event_type: type,
      occurred_at: at,
      actor: "Actor #{role}",
      actor_role: role,
      subject: subject_id,
      payload: payload,
      trust_marker: trust
    )
  end

  let(:log) do
    described_class.new(subject: subject_id).tap do |l|
      l.append(event("upgrade.install", at: "2027-03-01T10:00:00+00:00",
                     role: "installer",
                     payload: { "child" => "gtin:09506000134352/ser:BAT-77",
                                "slot" => "battery-slot-1" },
                     trust: "third_party_attested"))
      l.append(event("custody.transfer", at: "2027-06-01T10:00:00+00:00",
                     payload: { "to" => "Bob" }, trust: "self_declared"))
      l.append(event("inspection.stamp", at: "2027-09-01T10:00:00+00:00",
                     role: "verifier", payload: { "grade" => "A" },
                     trust: "log_anchored"))
    end
  end

  describe "chain integrity" do
    it "verifies a sound chain" do
      expect(log).to be_valid
      expect { log.verify! }.not_to raise_error
    end

    it "chains every entry onto the previous commitment" do
      expect(log.entries[0].previous).to eq(described_class::GENESIS)
      expect(log.entries[1].previous).to eq(log.entries[0].commitment)
      expect(log.entries[2].previous).to eq(log.entries[1].commitment)
    end

    it "exposes the head as the anchored commitment" do
      expect(log.head).to eq(log.entries.last.commitment)
      expect(log.head).to match(/\A[0-9a-f]{64}\z/)
    end

    it "detects a rewritten payload (never silently merged)" do
      tampered = log.entries.map do |entry|
        if entry.event.event_type == "custody.transfer"
          entry.tap { |e| e.event.payload = { "to" => "Mallory" } }
        else
          entry
        end
      end
      bad = described_class.new(subject: subject_id, entries: tampered)
      expect(bad).not_to be_valid
      expect { bad.verify! }
        .to raise_error(Unidpp::EventLog::IntegrityError, /commitment/)
    end

    it "detects a spliced entry (broken linkage)" do
      spliced = log.entries.dup
      spliced.delete_at(1)
      bad = described_class.new(subject: subject_id, entries: spliced)
      expect(bad.integrity_errors).not_to be_empty
    end

    it "uses a fresh salt per entry (salt discipline)" do
      salts = log.entries.map(&:salt)
      expect(salts.uniq.size).to eq(salts.size)
    end
  end

  describe "commit now, reveal later, never contradict" do
    it "reveals an entry consistent with its anchored commitment" do
      entry = log.reveal(log.entries.first.event.event_id)
      expect(entry).not_to be_nil
      expect(log.consistent_reveal?(entry)).to be true
      expect(entry.salt).to match(/\A[0-9a-f]+\z/)
    end

    it "refuses an inconsistent reveal" do
      entry = log.reveal(log.entries.first.event.event_id)
      entry.salt = "0" * 32
      expect(log.consistent_reveal?(entry)).to be false
    end

    it "is deterministic for identical event, salt and predecessor" do
      e = event("status.change", at: "2027-12-01T00:00:00+00:00",
                role: "regulator")
      log_a = described_class.new(subject: subject_id)
      log_b = described_class.new(subject: subject_id)
      entry_a = log_a.append(e, salt: "fixed-salt")
      entry_b = log_b.append(e, salt: "fixed-salt")
      expect(entry_a.commitment).to eq(entry_b.commitment)
    end

    it "is canonical over payload key order" do
      e1 = event("correction.record", at: "2027-12-01T00:00:00+00:00",
                 role: "eo", payload: { "a" => "1", "b" => "2" })
      e2 = event("correction.record", at: "2027-12-01T00:00:00+00:00",
                 role: "eo", payload: { "b" => "2", "a" => "1" })
      e1.event_id = e2.event_id = "correction-1"
      log_a = described_class.new(subject: subject_id)
      log_b = described_class.new(subject: subject_id)
      expect(log_a.append(e1, salt: "s").commitment)
        .to eq(log_b.append(e2, salt: "s").commitment)
    end
  end

  describe "as-of queries (notarized snapshots)" do
    it "returns the events that had occurred at T" do
      sub = log.as_of("2027-06-15T00:00:00+00:00")
      expect(sub.events.map(&:event_type))
        .to eq(%w[upgrade.install custody.transfer])
    end

    it "keeps the sub-chain prefix-consistent" do
      expect(log.as_of("2027-06-15T00:00:00+00:00")).to be_valid
      expect(log.as_of("2027-01-01T00:00:00+00:00")).to be_valid
      expect(log.as_of("2027-01-01T00:00:00+00:00").head)
        .to eq(described_class::GENESIS)
    end

    it "keeps the full log valid after an as-of view" do
      log.as_of("2027-06-15T00:00:00+00:00")
      expect(log).to be_valid
    end
  end

  describe "serialization round-trips (lutaml-model mappings)" do
    it "round-trips YAML with commitments intact" do
      round = described_class.from_yaml(log.to_yaml)
      expect(round).to be_valid
      expect(round.head).to eq(log.head)
      expect(round.entries.map(&:commitment)).to eq(log.entries.map(&:commitment))
      expect(round.subject).to eq(log.subject)
    end

    it "round-trips JSON" do
      round = described_class.from_json(log.to_json)
      expect(round).to be_valid
      expect(round.head).to eq(log.head)
    end

    it "round-trips the events themselves" do
      round = described_class.from_yaml(log.to_yaml)
      expect(round.events).to eq(log.events)
    end

    it "detects tampering in a loaded document" do
      doc = JSON.parse(log.to_json)
      doc["entries"][0]["event"]["payload"]["slot"] = "tampered-slot"
      loaded = described_class.from_json(JSON.generate(doc))
      expect(loaded).not_to be_valid
    end
  end

  describe "typed events and appender authorization" do
    it "accepts the authorized appender for each event kind" do
      expect(event("custody.transfer", at: "2027-01-01T00:00:00+00:00",
                   role: "custodian")).to be_authorized_appender
      expect(event("recall.campaign", at: "2027-01-01T00:00:00+00:00",
                   role: "regulator")).to be_authorized_appender
      expect(event("milestone.record", at: "2027-01-01T00:00:00+00:00",
                   role: "device")).to be_authorized_appender
    end

    it "rejects an unauthorized appender" do
      bad = event("recall.campaign", at: "2027-01-01T00:00:00+00:00",
                  role: "repairer")
      expect(bad).not_to be_authorized_appender
      expect { bad.authorize_appender! }
        .to raise_error(Unidpp::Event::UnauthorizedAppenderError)
    end

    it "carries the full E1-E15 taxonomy" do
      expect(Unidpp::Event::EVENT_TYPES).to include(
        "custody.transfer", "part.replace", "repair.perform", "product.modify",
        "software.update", "feature.unlock", "upgrade.install",
        "refurbish.perform", "consumable.replace", "recall.campaign",
        "correction.record", "status.change", "flag.security",
        "decompose.perform", "inspection.stamp", "milestone.record"
      )
    end

    it "grades trust per event" do
      expect(log.events.map(&:trust_marker))
        .to eq(%w[third_party_attested self_declared log_anchored])
    end

    it "assigns an event id exactly once at append" do
      e = event("status.change", at: "2027-12-01T00:00:00+00:00",
                role: "regulator")
      expect(e.event_id).to be_nil
      entry = described_class.new(subject: subject_id).append(e)
      expect(e.event_id).to eq(entry.event.event_id)
    end
  end
end
