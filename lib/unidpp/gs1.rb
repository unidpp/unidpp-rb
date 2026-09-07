# frozen_string_literal: true

require "strscan"

module Unidpp
  # GS1 key arithmetic shared by the identifier parsers: application
  # identifiers, element-string parsing (parenthesized and bracketed
  # human-readable forms) and the GS1 mod-10 check digit (GTIN-13/GTIN-14,
  # SSCC-18).
  module Gs1
    # Identity-relevant application identifiers (AI -> value shape).
    #   "00" SSCC (18 digits)   "01" GTIN-14
    #   "10" batch/lot (<= 20 GS1 AI charset)   "21" serial (<= 20 charset)
    IDENTITY_AIS = {
      "00" => /\A\d{18}\z/,
      "01" => /\A\d{14}\z/,
      "10" => /\A[\x21-\x22\x25-\x2F\x30-\x39\x3A-\x3F\x41-\x5A\x5F\x61-\x7A]{1,20}\z/,
      "21" => /\A[\x21-\x22\x25-\x2F\x30-\x39\x3A-\x3F\x41-\x5A\x5F\x61-\x7A]{1,20}\z/,
    }.freeze

    # Application identifiers accepted in a Digital Link URI path.
    DL_PATH_AIS = %w[00 01 10 21].freeze

    module_function

    # GS1 general specification check digit: from the rightmost digit of
    # the base (excluding the check position), multiply alternately by 3
    # and 1; the check digit completes the next multiple of ten.
    #
    # @param base [String, #to_s] digits without the check digit
    # @return [Integer] the check digit
    def check_digit(base)
      digits = base.to_s.chars.map(&:to_i)
      raise Error, "check digit base must be non-empty digits" if digits.empty?

      sum = digits.reverse.each_with_index.sum do |d, i|
        d * (i.even? ? 3 : 1)
      end
      (10 - (sum % 10)) % 10
    end

    # @param with_check [String] full code including trailing check digit
    # @return [Boolean]
    def valid_check_digit?(with_check)
      s = with_check.to_s
      return false unless /\A\d+\z/.match?(s)

      check_digit(s[0...-1]) == s[-1].to_i
    end

    # Parses a human-readable element string, e.g.
    #   (01)09506000134352(10)ABC-123(21)9876543
    # or the bracketed form
    #   [00]006141411234567890
    #
    # @param input [String]
    # @return [Hash{String => String}] AI -> value, in encounter order
    # @raise [Unidpp::Error] on malformed input
    def parse_element_string(input)
      opener = input.to_s.start_with?("[") ? "[" : "("
      values = {}
      scanner = StringScanner.new(input.to_s.strip)
      until scanner.eos?
        scanner.skip(/\s*/)
        break if scanner.eos?

        unless scanner.scan(/#{Regexp.escape(opener)}/)
          raise Error, "malformed element string at #{scanner.pos}: #{input}"
        end

        ai = scanner.scan(/\d{2,4}/)
        raise Error, "missing application identifier in #{input}" if ai.nil?

        scanner.skip(/\]/) if opener == "["
        scanner.skip(/\)/) if opener == "("
        # value runs until the next opener or end of string
        value = scanner.scan_until(/(?=#{Regexp.escape(opener)}|\z)/) || scanner.rest
        value = value.sub(/\s+\z/, "")
        raise Error, "empty value for AI (#{ai})" if value.empty?

        values[ai] = value
      end
      values
    end

    # Validates AI values against the identity AI table, including the
    # mod-10 check digits of SSCC (00) and GTIN (01).
    #
    # @param values [Hash{String => String}]
    # @raise [Unidpp::Error] on an unsupported AI, bad shape or bad check
    #   digit
    def validate_identity_ais!(values)
      values.each do |ai, value|
        pattern = IDENTITY_AIS[ai]
        raise Error, "unsupported identity AI (#{ai})" if pattern.nil?
        raise Error, "invalid value for AI (#{ai}): #{value}" unless pattern.match?(value)
      end
      %w[00 01].each do |ai|
        next unless (code = values[ai])

        raise Error, "invalid check digit for AI (#{ai}): #{code}" unless valid_check_digit?(code)
      end
    end
  end
end
