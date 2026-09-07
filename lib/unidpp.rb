# frozen_string_literal: true

# UniDPP — Ruby library for the international Digital Product Passport
# framework (PLAN.md invariants I1–I14; see https://github.com/unidpp).
#
# Loading discipline: this file is the only require point. Every other
# constant is lazily loaded through autoload entries declared here (and,
# for the Unidpp::Registry namespace, in unidpp/registry.rb) — no
# require_relative anywhere inside lib/.
require "lutaml/model"

module Unidpp
  class Error < StandardError; end

  autoload :VERSION,         "unidpp/version"
  autoload :CanonicalJson,   "unidpp/canonical_json"
  autoload :Gs1,             "unidpp/gs1"
  autoload :ProductIdentifier, "unidpp/identifier"
  autoload :ProfileManifest, "unidpp/manifest"
  autoload :ProfileAxes,     "unidpp/manifest"
  autoload :TriggerPredicate, "unidpp/manifest"
  autoload :CryptoSuiteBinding, "unidpp/manifest"
  autoload :PassportLink,    "unidpp/link"
  autoload :LinkInterval,    "unidpp/link"
  autoload :Event,           "unidpp/event"
  autoload :EventLog,        "unidpp/event_log"
  autoload :Verdict,         "unidpp/verdict"
  autoload :Quantity,        "unidpp/quantity"
  autoload :Registry,        "unidpp/registry"
end
