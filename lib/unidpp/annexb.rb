# frozen_string_literal: true

require "digest"

module Unidpp
  # The Annex B binary canonical encoding (TODO 237), written from the
  # specification: the framing rule (each field a little-endian u32
  # length prefix and its bytes, in the declared field order), the
  # domain tags, and the per-object derivations. The vendored golden
  # vectors carry the reference `canonical_hex` pins; the suite
  # asserts byte identity — this implementation agrees with the
  # reference or the suite fails. That is the cross-implementation
  # contract.
  module AnnexB
    module_function

    SEGMENT_COMMITMENT = "UNIDPP-GRID/SEGMENT-COMMITMENT"
    SPINE_LEAF = "UNIDPP-GRID/SPINE-LEAF"
    SPINE_NODE = "UNIDPP-GRID/SPINE-NODE"
    SPINE_DIGEST = "UNIDPP-GRID/SPINE-DIGEST"

    REVEAL_TOKENS = {
      "Open" => "open",
      "PairingGated" => "pairing-gated",
      "OriginSealed" => "origin-sealed",
      "Escrowed" => "escrowed"
    }.freeze

    CLAIM_TOKENS = {
      "conformity" => "conformity",
      "commitment-hash" => "commitment-hash",
      "freshness" => "freshness"
    }.freeze

    EVIDENCE_TOKENS = {
      "verified-direct" => "verified-direct",
      "attested-by-authority" => "attested-by-authority",
      "explicitly-unavailable" => "explicitly-unavailable"
    }.freeze

    LEVEL_ORDINALS = {
      "l0" => 0, "l1" => 1, "l2" => 2, "l3" => 3, "l4" => 4, "l5" => 5
    }.freeze

    def sha256(data)
      Digest::SHA256.digest(data)
    end

    def le_u32(value)
      [value].pack("V")
    end

    def le_u64(value)
      [value].pack("Q<")
    end

    def part(bytes)
      # UTF-8 strings keep their bytes (relabelled, never transcoded):
      # the canonical bytes ARE the UTF-8 encoding, and the framing
      # layer works in binary throughout.
      binary = if bytes.is_a?(String)
                 bytes.dup.force_encoding(Encoding::BINARY)
               else
                 bytes.pack("C*")
               end
      le_u32(binary.bytesize) + binary
    end

    # The canonical form: fields in declared order, each
    # length-prefixed.
    def canonical_fields(parts)
      parts.map { |p| part(p) }.join
    end

    # The one framing rule: tag || 0x00 || payload.
    def domain_frame(tag, payload)
      tag + "\x00".b + payload
    end

    # Hash in a domain: sha256 over the domain-framed canonical parts.
    def hash_in(domain, parts)
      sha256(domain_frame(domain, canonical_fields(parts)))
    end

    # Wire forms carry hashes either hex-encoded or as byte arrays.
    def as_bytes(value)
      value.is_a?(String) ? [value].pack("H*") : value.pack("C*")
    end

    # A sorted, deduplicated list joined with the unit separator
    # (U+001F).
    def canon_list(values)
      values.uniq.sort.join("\x1f")
    end

    def policy_canonical(policy)
      parts = [
        policy["policy_id"],
        le_u64(policy["version"]),
        policy["authority"],
        REVEAL_TOKENS.fetch(policy["reveal"], policy["reveal"]),
        policy["valid_from"],
        canon_list(policy["readers"]),
        canon_list(policy["verifiers"]),
        canon_list(policy["writers"]),
        canon_list(policy["suites"])
      ]
      parts << policy["valid_to"] unless policy["valid_to"].nil?
      parts << le_u64(policy["superseded_by"]) unless policy["superseded_by"].nil?
      canonical_fields(parts)
    end

    def h_pair(left, right)
      a, b = [left, right].minmax
      hash_in(SPINE_NODE, [a, b])
    end

    def commit_state(state)
      hash_in(SEGMENT_COMMITMENT, [state])
    end

    def spine_root(commitments)
      level = commitments.keys.sort.map do |id|
        hash_in(SPINE_LEAF, [id, as_bytes(commitments[id])])
      end
      return "\x00".b * 32 if level.empty?

      while level.size > 1
        level = level.each_slice(2).map do |pair|
          pair.size == 2 ? h_pair(pair[0], pair[1]) : h_pair(pair[0], pair[0])
        end
      end
      level.first
    end

    def spine_digest(version, commitments)
      buf = le_u64(version) + spine_root(commitments)
      commitments.keys.sort.each do |id|
        buf += le_u32(id.bytesize) + id + as_bytes(commitments[id])
      end
      hash_in(SPINE_DIGEST, [buf])
    end

    def request_canonical(request)
      canonical_fields(
        [
          request["verifier"],
          request["subject"],
          request["profile"],
          request["segment"],
          request["at"]
        ]
      )
    end

    def response_canonical(response)
      outcome = response["outcome"]
      payload = outcome.reject { |k, _| k == "outcome" }
      canonical_fields(
        [
          as_bytes(response["request_digest"]),
          outcome["outcome"],
          *payload.values,
          response["governing_policy"],
          le_u64(response["governing_policy_version"]),
          response["custodian"]
        ]
      )
    end

    def route_canonical(route)
      parts = [le_u64(route["steps"].size)]
      route["steps"].each do |step|
        kind = step["step"]
        parts << kind
        case kind
        when "resolve" then parts << step["subject"]
        when "transport" then parts << step["mode"] << step["counterpart"]
        when "document" then parts << step["kind"] << as_bytes(step["digest"])
        when "substitution" then parts << step["data_class"] << step["service"]
        when "classify"
          e = step["entry"]
          parts << e["class"] << e["element_set"] <<
            EVIDENCE_TOKENS.fetch(e["evidence"], e["evidence"]) <<
            e["governing_policy"] << le_u64(e["governing_policy_version"]) <<
            e["reading"] << e["as_of"]
        when "gap" then parts << step["data_class"] << step["reason"]
        end
      end
      canonical_fields(parts)
    end

    def route_digest(route)
      sha256(route_canonical(route))
    end

    def report_canonical(report)
      parts = [
        report["subject"],
        report["profile"],
        report["verified_at"],
        le_u64(report["route"] ? 1 : 0)
      ]
      parts << route_digest(report["route"]) if report["route"]
      parts << le_u64(report["entries"].size)
      report["entries"].each do |e|
        parts << e["class"] << e["element_set"] <<
          EVIDENCE_TOKENS.fetch(e["evidence"], e["evidence"]) <<
          e["governing_policy"] << le_u64(e["governing_policy_version"]) <<
          e["reading"] << e["as_of"]
      end
      canonical_fields(parts)
    end

    def statement_canonical(statement)
      canonical_fields(
        [
          statement["segment"],
          as_bytes(statement["state_commitment"]),
          CLAIM_TOKENS.fetch(statement["claim"], statement["claim"]),
          statement["value"],
          statement["as_of"],
          statement["governing_policy"],
          le_u64(statement["governing_policy_version"]),
          statement["subject"]
        ]
      )
    end

    def descriptor_token(descriptor)
      [descriptor["temporal"], descriptor["content"], descriptor["derivation"],
       descriptor["exchange"], descriptor["granularity"]].join("·")
    end

    def frozen_view_canonical(view)
      parts = [
        view["subject"],
        descriptor_token(view["descriptor"]),
        view["lens"]["profile"]
      ]
      view["lens"]["transforms"].each do |step|
        parts << step["reference"] << le_u64(step["version"])
      end
      view["lens"]["input_segments"].each do |name, segment|
        parts << name << segment
      end
      parts << as_bytes(view["payload"])
      view["inputs"].each do |input|
        parts << input["name"] << commit_state(as_bytes(input["bytes"]))
      end
      view["instructions"].each { |instruction| parts << instruction }
      parts << view["notarized_at"]
      parts << spine_digest(view["bundle"]["spine"]["spine"]["version"],
                            view["bundle"]["spine"]["spine"]["commitments"])
      canonical_fields(parts)
    end

    def declaration_canonical(declaration)
      postures = declaration["postures"].sort_by { |p| p["data_class"] }
      parts = [
        declaration["declarer"],
        declaration["counterpart"],
        le_u64(declaration["version"])
      ]
      postures.each do |posture|
        parts << posture["data_class"]
        parts << [LEVEL_ORDINALS.fetch(posture["level"], 255)].pack("C")
        parts << posture["recognition"]
        posture["transports"].sort.each { |transport| parts << transport }
        parts << (posture["escalation"] || "")
        parts << (posture["reciprocity"] || "")
      end
      parts << declaration["valid_from"]
      parts << (declaration["valid_to"] || "")
      canonical_fields(parts)
    end

    def mapping_item_canonical(item)
      parts = [item["source"], item["target"], le_u64(item["version"])]
      kind = item["kind"]
      case kind["tier"]
      when "deterministic"
        parts << "tier-1" << kind["transform"]
      when "correspondence"
        parts << "tier-2"
        kind["scope"].sort.each { |scope| parts << scope }
        parts << kind["residual"] << kind["attester"]
      when "no-mapping"
        parts << "tier-3" << kind["note"]
      else
        raise ArgumentError, "unknown mapping tier `#{kind['tier']}'"
      end
      canonical_fields(parts)
    end
  end
end
