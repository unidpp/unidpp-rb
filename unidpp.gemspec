# frozen_string_literal: true

lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "unidpp/version"

Gem::Specification.new do |spec|
  spec.name          = "unidpp"
  spec.version       = Unidpp::VERSION
  spec.summary       = "UniDPP — Digital Product Passport model, event log and FERIN/ISO 19135 registry client"
  spec.description   = "Ruby library for the UniDPP international Digital Product Passport framework: " \
                       "scheme-agnostic product identifiers (GS1 Digital Link, ISO/IEC 15459, GB/T 33993-style, URN), " \
                       "profile manifests (jurisdiction x sector x characteristic axes, trigger predicates, " \
                       "capability classes S0-S3, crypto-suite bindings), typed relationship edges with visibility " \
                       "classes, hash-chained append-only event logs with salted commitments, graded-trust verdicts, " \
                       "quantities with registered unit URIs, and a federated-registry client " \
                       "(FERIN/ISO 19135 items, statuses, supersession chains, applicability as-of queries)."
  spec.authors       = ["UniDPP"]
  spec.license       = "MIT"
  spec.homepage      = "https://github.com/unidpp/unidpp-rb"

  spec.files         = Dir["lib/**/*.rb"]
  spec.bindir        = "exe"
  spec.executables   = Dir["exe/*"].map { |f| File.basename(f) }

  spec.required_ruby_version = ">= 3.0"

  spec.add_dependency "lutaml-model", "~> 0.8"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.13"
end
