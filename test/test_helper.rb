# frozen_string_literal: true

require "simplecov"
SimpleCov.start

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sigstore/cosign/verify"
require "sigstore/internal/merkle"

require "test-unit"
require "webmock/test_unit"
require "vcr"
require "json"
require "timecop"

WebMock.disable_net_connect!

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into :webmock
  config.default_cassette_options = { record: :new_episodes }
end
