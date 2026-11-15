# frozen_string_literal: true

require "ed25519"
require "digest"

module Unidpp
  # The S13 trust layer (XB-6/7): verify the seam's signed envelopes
  # offline — the requester's, the custodian's and the authority's
  # signatures all ride the S13-MESSAGE domain over canonical bytes,
  # and the choreography journal replays from the envelopes alone.
  # The graph is the caller's projection: node id → that node's
  # anchored keys ({ key_id => raw public bytes }), the same
  # resolution discipline the native TrustGraph applies — a valid
  # signature from any other node's key is not this envelope.
  module S13
    module_function

    DOMAIN = "UNIDPP-SIGNATIF/S13-MESSAGE"

    # The signatif suite codes (Annex B): the one byte a key id's
    # digest rides over, ahead of the public key bytes.
    SUITE_CODES = {
      "ecdsa-p256" => 1,
      "sm2" => 2,
      "ml-dsa-44" => 3,
      "ml-dsa-65" => 4,
      "ml-dsa-87" => 5,
      "ed25519" => 6,
      "slh-dsa-128s" => 7,
      "slh-dsa-192s" => 8
    }.freeze

    # The native keyring's derivation label (Annex B): the Ed25519
    # seed is sha256 over this label and the caller's seed — the same
    # keys the Rust side derives, and Ed25519's determinism makes the
    # signatures byte-identical.
    SEED_LABEL = "UNIDPP-SIGNATIF/KEY-SEED"

    SeededKey = Struct.new(:signing_key, :public_bytes, :key_id) do
      def sign_framed(payload)
        domain = "#{DOMAIN}\x00".b + payload
        signing_key.sign(domain)
      end
    end

    def seeded_key(seed)
      seed = seed.encode(Encoding::UTF_8) if seed.is_a?(String)
      scalar = Digest::SHA256.digest(SEED_LABEL.b + seed)
      signing_key = Ed25519::SigningKey.new(scalar)
      public_bytes = signing_key.verify_key.to_bytes
      SeededKey.new(signing_key, public_bytes, key_id("ed25519", public_bytes))
    end

    def issue_request(request, requester, key)
      {
        "request" => request,
        "requester" => requester,
        "signature" => slot_for(key, AnnexB.request_canonical(request))
      }
    end

    def issue_response(response, custodian, key)
      signed = response.merge("custodian" => custodian)
      {
        "response" => signed,
        "signature" => slot_for(key, AnnexB.response_canonical(signed))
      }
    end

    def countersign(signed_response, authority, sequence, key)
      payload = authority_payload(signed_response["response"], sequence)
      {
        "signed" => signed_response,
        "authority" => authority,
        "authority_signature" => slot_for(key, payload),
        "sequence" => sequence
      }
    end

    def slot_for(key, canonical_bytes)
      {
        "suite" => "ed25519",
        "key_id" => key.key_id,
        "signature" => key.sign_framed(canonical_bytes).unpack("C*")
      }
    end

    def key_id(suite, public_key)
      code = SUITE_CODES[suite]
      raise Error, "unknown suite `#{suite}`" unless code
      digest = AnnexB.sha256([code].pack("C") + public_key)
      "k-#{digest.unpack1("H16")}"
    end

    def authority_payload(response, sequence)
      AnnexB.canonical_fields(
        [
          AnnexB.as_bytes(response["request_digest"]),
          AnnexB.le_u64(sequence),
          response["governing_policy"],
          AnnexB.le_u64(response["governing_policy_version"])
        ]
      )
    end

    def domain_framed(payload)
      "#{DOMAIN}\x00".b + payload
    end

    def verify_request(signed, graph)
      verify_under(graph, signed["requester"], signed["signature"],
                   domain_framed(AnnexB.request_canonical(signed["request"])))
    end

    def verify_response(signed, graph)
      verify_under(graph, signed["response"]["custodian"], signed["signature"],
                   domain_framed(AnnexB.response_canonical(signed["response"])))
    end

    # The non-repudiable answer (XB-7): the custodian's signature AND
    # the authority's counter-signature over the answer's identity and
    # place, at the exact expected sequence (a stale sequence is a
    # replayed answer).
    def verify_non_repudiable(countersigned, graph, expected_sequence)
      custodian = verify_response(countersigned["signed"], graph)
      return custodian unless custodian[:ok]

      if countersigned["sequence"] != expected_sequence
        return { ok: false,
                 why: "s13 non-repudiation: stale sequence #{countersigned['sequence']} (expected #{expected_sequence}) — a replayed answer" }
      end

      verify_under(
        graph,
        countersigned["authority"],
        countersigned["authority_signature"],
        domain_framed(authority_payload(countersigned["signed"]["response"], countersigned["sequence"]))
      )
    end

    # Replay the choreography from the journal alone (XB-6): every
    # entry verifies under the graph, every answer binds to a
    # journaled request's digest, and every counter-signature sits at
    # its exact monotone place per (subject, custodian), from 1. The
    # decisions come back in journal sequence.
    def replay(journal, graph)
      decisions = []
      subjects = {}
      sequences = Hash.new(0)
      index = 0
      journal["entries"].each do |entry|
        index += 1
        if entry.key?("request")
          check = verify_request(entry, graph)
          return { ok: false, why: "entry #{index}: #{check[:why]}" } unless check[:ok]
          subjects[AnnexB.sha256(AnnexB.request_canonical(entry["request"])).unpack1("H32")] =
            entry["request"]["subject"]
        elsif entry.key?("response")
          check = verify_response(entry, graph)
          return { ok: false, why: "entry #{index}: #{check[:why]}" } unless check[:ok]
          digest = digest_hex(entry["response"]["request_digest"])
          return { ok: false, why: "entry #{index}: an answer is bound to no journaled request" } unless subjects.key?(digest)
          decisions << decision_of(entry["response"])
        else
          digest = digest_hex(entry["signed"]["response"]["request_digest"])
          return { ok: false, why: "entry #{index}: an answer is bound to no journaled request" } unless subjects.key?(digest)
          subject = subjects[digest]
          place = "#{subject}|#{entry['signed']['response']['custodian']}"
          expected = sequences[place] + 1
          check = verify_non_repudiable(entry, graph, expected)
          return { ok: false, why: "entry #{index}: #{check[:why]}" } unless check[:ok]
          sequences[place] = entry["sequence"]
          decisions << decision_of(entry["signed"]["response"])
        end
      end
      { ok: true, decisions: decisions }
    end

    def verify_under(graph, node, slot, payload)
      keys = graph[node]
      return { ok: false, why: "s13 node `#{node}` has no such keys" } unless keys
      key_bytes = keys[slot["key_id"]]
      return { ok: false, why: "s13 node `#{node}` has no such key `#{slot['key_id']}`" } unless key_bytes
      signature = slot["signature"]
      return { ok: false, why: "the slot is framed-only (nothing to verify)" } unless signature
      signature = signature.pack("C*") if signature.is_a?(Array)
      begin
        Ed25519::VerifyKey.new(key_bytes).verify(signature, payload)
        { ok: true }
      rescue Ed25519::VerifyError, ArgumentError
        { ok: false, why: "the signature does not verify under `#{node}`'s key `#{slot['key_id']}`" }
      end
    end

    # The digest rides JSON as either its hex form or the byte array.
    def digest_hex(value)
      return value if value.is_a?(String) && value.match?(/\A[0-9a-f]{64}\z/)
      bytes = value.is_a?(Array) ? value.pack("C*") : value
      bytes.unpack1("H32")
    end

    def decision_of(response)
      {
        request_digest_hex: digest_hex(response["request_digest"]),
        outcome: response["outcome"]["outcome"],
        governing_policy: response["governing_policy"],
        governing_policy_version: response["governing_policy_version"]
      }
    end
  end
end
