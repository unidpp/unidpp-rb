# frozen_string_literal: true

require "openssl"

module Unidpp
  # The Tier-A carrier codec and its verifier (the native framing,
  # R11's unification): the tag-length-value encoding the issuers
  # mint and the offline CLI decodes, now readable in Ruby. The
  # decoder mirrors unidpp-core's tier_a packer byte for byte; the
  # signing body reconstructs as the payload's canonical bytes with
  # the signature block emptied — what every slot's signature covers,
  # framed in the ARTIFACT-EVENT domain. The verifier walks the
  # honesty ladder the estate's other verifiers walk: taint, the
  # validity window, freshness, the recall guard, and each slot's
  # signature under the caller's anchored keys — ECDSA-P256 verifies
  # through the stdlib OpenSSL binding; any other suite defers
  # honestly (a missing binding degrades the verdict, it never
  # silently passes). The verdict is a graded document, never boolean.
  module TierA
    module_function

    DOMAIN = "UNIDPP-SIGNATIF/ARTIFACT-EVENT"

    TAG_PRODUCT_ID = 0x01
    TAG_RESOLVER_URI = 0x02
    TAG_PASSPORT_ID = 0x03
    TAG_EO_ID = 0x04
    TAG_STATUS = 0x05
    TAG_SAFETY = 0x06
    TAG_VALIDITY_FROM = 0x07
    TAG_VALIDITY_TO = 0x08
    TAG_AS_OF = 0x09
    TAG_LOG_HEAD = 0x0A
    TAG_SIG_COUNT = 0x0B
    TAG_SIG_SLOT = 0x0C
    SIG_PLACEHOLDER = 0xFFFF

    SUITE_BY_CODE = {
      1 => "ecdsa-p256",
      2 => "sm2",
      3 => "ml-dsa-44",
      4 => "ml-dsa-65",
      5 => "ml-dsa-87"
    }.freeze
    CODE_BY_SUITE = SUITE_BY_CODE.invert.freeze

    STATUSES = %w[
      issued suspended invalidated non-conformant consumed transformed
      end-of-waste archived
    ].freeze
    SAFETIES = %w[none recall-active security-flagged].freeze

    class CarrierError < StandardError; end

    class Reader
      def initialize(data)
        @data = data
        @pos = 0
      end

      def remaining?
        @data.bytesize - @pos
      end

      def take(n)
        raise CarrierError, "canonical stream truncated at offset #{@pos} (need #{n} bytes)" if remaining? < n
        out = @data[@pos, n]
        @pos += n
        out
      end

      def read_tag
        take(1).unpack1("C")
      end

      def read_u16
        take(2).unpack1("v")
      end

      def read_u32
        take(4).unpack1("V")
      end

      def read_bytes
        take(read_u32)
      end

      def read_str
        read_bytes.force_encoding(Encoding::UTF_8)
      end

      def read_opt_str
        case read_tag
        when 0 then nil
        when 1 then read_str
        else raise CarrierError, "bad optional tag"
        end
      end

      def read_opt_hash
        case read_tag
        when 0 then nil
        when 1 then take(32).unpack1("H*")
        else raise CarrierError, "bad optional tag"
        end
      end
    end

    def decode(payload_bytes)
      r = Reader.new(payload_bytes)
      fields = {}
      signatures = []
      while r.remaining? > 0
        case r.read_tag
        when TAG_PRODUCT_ID then fields[:product_id] = r.read_str
        when TAG_RESOLVER_URI then fields[:resolver_uri] = r.read_str
        when TAG_PASSPORT_ID then fields[:passport_id] = r.read_str
        when TAG_EO_ID then fields[:eo_id] = r.read_str
        when TAG_STATUS
          token = r.read_str
          raise CarrierError, "unknown status `#{token}`" unless STATUSES.include?(token)
          fields[:status] = token
        when TAG_SAFETY
          token = r.read_str
          raise CarrierError, "unknown safety `#{token}`" unless SAFETIES.include?(token)
          fields[:safety] = token
        when TAG_VALIDITY_FROM then fields[:validity_from] = r.read_str
        when TAG_VALIDITY_TO then fields[:validity_to] = r.read_opt_str
        when TAG_AS_OF then fields[:as_of] = r.read_str
        when TAG_LOG_HEAD then fields[:log_head] = r.read_opt_hash
        when TAG_SIG_COUNT
          r.read_tag.times do
            slot_tag = r.read_tag
            raise CarrierError, "expected the signature-slot tag, read #{slot_tag}" unless slot_tag == TAG_SIG_SLOT
            code = r.read_tag
            suite = SUITE_BY_CODE[code]
            raise CarrierError, "unknown suite code #{code}" unless suite
            key_id = r.read_bytes.force_encoding(Encoding::UTF_8)
            length = r.read_u16
            signatures << {
              suite: suite,
              key_id: key_id,
              signature: length == SIG_PLACEHOLDER ? nil : r.take(length)
            }
          end
        else
          raise CarrierError, "unknown field tag"
        end
      end
      %i[product_id resolver_uri passport_id eo_id status safety validity_from as_of].each do |field|
        raise CarrierError, "missing #{field}" unless fields[field]
      end
      {
        product_id: fields.fetch(:product_id),
        resolver_uri: fields.fetch(:resolver_uri),
        passport_id: fields.fetch(:passport_id),
        eo_id: fields.fetch(:eo_id),
        status: fields.fetch(:status),
        safety: fields.fetch(:safety),
        validity: { from: fields.fetch(:validity_from), to: fields[:validity_to] },
        as_of: fields.fetch(:as_of),
        log_head: fields[:log_head],
        signatures: signatures
      }
    end

    def decode_hex(hex)
      raise CarrierError, "the carrier hex is odd-length" if hex.length.odd?
      decode([hex].pack("H*"))
    end

    class Writer
      def initialize
        @parts = +"".b
      end

      def write_tag(tag)
        @parts << [tag].pack("C")
        self
      end

      def write_u16(v)
        @parts << [v].pack("v")
        self
      end

      def write_u32(v)
        @parts << [v].pack("V")
        self
      end

      def write_bytes(data)
        write_u32(data.bytesize)
        @parts << data
        self
      end

      def write_str(text)
        write_bytes(text.encode(Encoding::UTF_8))
      end

      def write_opt_str(text)
        text.nil? ? write_tag(0) : (write_tag(1) && write_str(text))
        self
      end

      def write_opt_hash(hex)
        return write_tag(0) if hex.nil?
        write_tag(1)
        @parts << [hex].pack("H*")
        self
      end

      def into_bytes
        @parts.dup
      end
    end

    def write_payload(w, payload)
      w.write_tag(TAG_PRODUCT_ID).write_str(payload[:product_id])
      w.write_tag(TAG_RESOLVER_URI).write_str(payload[:resolver_uri])
      w.write_tag(TAG_PASSPORT_ID).write_str(payload[:passport_id])
      w.write_tag(TAG_EO_ID).write_str(payload[:eo_id])
      w.write_tag(TAG_STATUS).write_str(payload[:status])
      w.write_tag(TAG_SAFETY).write_str(payload[:safety])
      w.write_tag(TAG_VALIDITY_FROM).write_str(payload[:validity][:from])
      w.write_tag(TAG_VALIDITY_TO).write_opt_str(payload[:validity][:to])
      w.write_tag(TAG_AS_OF).write_str(payload[:as_of])
      w.write_tag(TAG_LOG_HEAD).write_opt_hash(payload[:log_head])
    end

    def write_signature_block(w, signatures)
      w.write_tag(TAG_SIG_COUNT).write_tag([signatures.length, 255].min)
      signatures.first(255).each do |slot|
        code = CODE_BY_SUITE[slot[:suite]]
        raise CarrierError, "unknown suite `#{slot[:suite]}`" unless code
        w.write_tag(TAG_SIG_SLOT).write_tag(code).write_bytes(slot[:key_id].encode(Encoding::UTF_8))
        signature = slot[:signature]
        if signature.nil?
          w.write_u16(SIG_PLACEHOLDER)
        else
          raise CarrierError, "signature exceeds u16 framing" if signature.bytesize > 0xFFFF
          w.write_u16(signature.bytesize)
          w.instance_variable_get(:@parts) << signature
        end
      end
    end

    def encode(payload)
      w = Writer.new
      write_payload(w, payload)
      write_signature_block(w, payload[:signatures])
      w.into_bytes
    end

    # The signing body: the payload's canonical bytes with the
    # signature block omitted — ending with the EMPTY count block
    # (the bytes the slots' signatures frame around).
    def signing_body(payload)
      w = Writer.new
      write_payload(w, payload)
      w.write_tag(TAG_SIG_COUNT).write_tag(0)
      w.into_bytes
    end

    def domain_framed(payload_bytes)
      "#{DOMAIN}\x00".b + payload_bytes
    end

    def duration_ms(token)
      m = token.match(/\AP(?:(\d+)D)?(?:T(?:(\d+)H)?)?\z/)
      return nil unless m
      ((m[1] || 0).to_i * 86_400 + (m[2] || 0).to_i * 3_600) * 1_000
    end

    def parse_iso(text)
      Time.iso8601(text)
    rescue ArgumentError
      nil
    end

    def assess_freshness(as_of, required, now)
      return "unknown" if required.nil?
      t_now = parse_iso(now)
      t_as_of = parse_iso(as_of)
      return "unknown" if t_now.nil? || t_as_of.nil?
      budget = duration_ms(required)
      return "unknown" if budget.nil?
      ((t_now - t_as_of) * 1000).ceil <= budget ? "fresh" : "stale"
    end

    # The lean honesty ladder over a decoded payload: the graded
    # verdict document. Options: anchors ({ key_id => public_hex }),
    # now (ISO 8601; default the current moment), reading,
    # required_freshness (an ISO-8601 duration token), tainted (a
    # passport-id list), revocations (a key-id list), minimum_marker.
    def verify(payload, options = {})
      now = options[:now] || Time.now.utc.iso8601
      reading = options[:reading] || "current_state"
      anchors = options[:anchors] || {}
      findings = []
      outcomes = []
      checks = 1
      passed = 1
      verified = 0
      failed = 0
      unsupported = 0
      anchored_keys = 0
      strongest = "unsigned"

      if (options[:tainted] || []).include?(payload[:passport_id])
        findings << { severity: "error", code: "tainted",
                      message: "passport #{payload[:passport_id]} is tainted" }
        outcomes << "fail"
      end

      checks += 1
      to = payload[:validity][:to]
      if now < payload[:validity][:from] || (!to.nil? && now > to)
        findings << { severity: "error", code: "validity-window",
                      message: "carrier outside validity window [#{payload[:validity][:from]}, #{to || 'open'}]" }
        outcomes << "fail"
      else
        passed += 1
      end

      freshness = assess_freshness(payload[:as_of], options[:required_freshness], now)
      if payload[:safety] == "recall-active" && freshness == "stale"
        findings << { severity: "error", code: "recall-stale",
                      message: "recall flag present but data is stale — cannot pass" }
        outcomes << "fail"
      end
      outcomes << (freshness == "stale" ? "degraded" : freshness == "unknown" ? "pass" : "pass")
      checks += 1
      passed += 1 if freshness != "stale"

      body = signing_body(payload)
      framed = domain_framed(body)
      payload[:signatures].each do |slot|
        voided = (options[:revocations] || []).include?(slot[:key_id])
        if voided
          failed += 1
          checks += 1
          findings << { severity: "error", code: "signature-voided",
                        message: "signature by #{slot[:key_id]} voided under #{reading} reading" }
          outcomes << "fail"
          next
        end
        signature = slot[:signature]
        if signature.nil?
          unsupported += 1
          findings << { severity: "warning", code: "suite-unsupported",
                        message: "the slot is framed-only (nothing to verify)" }
          outcomes << "degraded"
          next
        end
        public_hex = anchors[slot[:key_id]]
        if public_hex.nil?
          findings << { severity: "warning", code: "key-unanchored",
                        message: "slot names key #{slot[:key_id]} but the anchor set pins nothing: the verifier's trust configuration does not cover this signer" }
          outcomes << "degraded"
          next
        end
        anchored_keys += 1
        if slot[:suite] == "ecdsa-p256"
          if ecdsa_p256_verifies(public_hex, framed, signature)
            verified += 1
            checks += 1
            passed += 1
            marker = "third-party-attested"
            strongest = marker if strongest == "unsigned"
          else
            failed += 1
            checks += 1
            findings << { severity: "error", code: "signature-invalid",
                          message: "signature by #{slot[:key_id]} (#{slot[:suite]}) failed verification" }
            outcomes << "fail"
          end
        else
          unsupported += 1
          findings << { severity: "warning", code: "suite-unsupported",
                        message: "suite #{slot[:suite]} deferred in this build: no binding computes it here" }
          outcomes << "degraded"
        end
      end

      marker_ok = strongest == "unsigned" ||
                  strongest == (options[:minimum_marker] || "unsigned") ||
                  options[:minimum_marker].nil?
      trust_coverage = 1
      if !options[:minimum_marker].nil? && !marker_ok
        trust_coverage = 0
        findings << { severity: "warning", code: "below-minimum-marker",
                      message: "achieved #{strongest}, policy requires #{options[:minimum_marker]}" }
        outcomes << "degraded"
      end

      {
        reading: reading,
        outcome: outcomes.include?("fail") ? "fail" : outcomes.include?("degraded") ? "degraded" : "pass",
        freshness: freshness,
        coverage: {
          checks: checks,
          passed: passed,
          signatures: {
            total: payload[:signatures].length,
            verified: verified,
            failed: failed,
            unsupported: unsupported
          },
          anchor_coverage: payload[:signatures].empty? ? 0 : anchored_keys.to_f / payload[:signatures].length,
          trust_coverage: trust_coverage
        },
        findings: findings,
        as_of: now,
        achieved_marker: strongest
      }
    end

    def ecdsa_p256_verifies(public_hex, framed, signature)
      key = OpenSSL::PKey::EC.new(spki_der(public_hex))
      digest = OpenSSL::Digest::SHA256.digest(framed)
      key.dsa_verify_asn1(digest, der_signature(signature))
    rescue OpenSSL::PKey::ECError, StandardError
      false
    end

    def spki_der(public_hex)
      point = [public_hex].pack("H*")
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
          OpenSSL::ASN1::ObjectId("prime256v1")
        ]),
        OpenSSL::ASN1::BitString.new(point)
      ]).to_der
    end

    # The slots carry the raw r||s form (64 bytes); the stdlib
    # binding wants DER.
    def der_signature(raw)
      r = raw[0, 32]
      s = raw[32, 32]
      pad = ->(b) { b.bytesize > 0 && b.getbyte(0) & 0x80 != 0 ? "\x00".b + b : b }
      rp = pad.call(r)
      sp = pad.call(s)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(rp, 2)),
        OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(sp, 2))
      ]).to_der
    end
  end
end
