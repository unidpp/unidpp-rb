# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "unidpp"

require "bigdecimal"
require "json"

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.disable_monkey_patching!
  config.order = :random
  config.filter_run_when_matching :focus

  Kernel.srand config.seed
end

FIXTURES = File.expand_path("fixtures", __dir__) unless defined?(FIXTURES)
