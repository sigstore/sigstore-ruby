# frozen_string_literal: true

require "simplecov"
SimpleCov.configure do
  add_filter "test/"
end
SimpleCov.start if ENV["COVERAGE"]

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sigstore"

require "test-unit"
require "webmock/test_unit"
require "vcr"
require "json"
require "timecop"
require "tmpdir"

WebMock.disable_net_connect!

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into :webmock
  config.default_cassette_options = { record: :new_episodes }
end

class Test::Unit::TestCase
  setup
  def env_home_setup
    @xdg_data_home = ENV.fetch("XDG_DATA_HOME", nil)
    @xdg_cache_home = ENV.fetch("XDG_CACHE_HOME", nil)
    @home = ENV.fetch("HOME", nil) # rubocop:disable Style/EnvHome
    @tmp_home = Dir.mktmpdir

    ENV.update(
      "XDG_DATA_HOME" => nil,
      "XDG_CACHE_HOME" => nil,
      "HOME" => @tmp_home
    )
  end

  cleanup
  def env_home_cleanup
    FileUtils.remove_entry_secure(@tmp_home)
    ENV.update(
      "XDG_DATA_HOME" => @xdg_data_home,
      "XDG_CACHE_HOME" => @xdg_cache_home,
      "HOME" => @home
    )
  end
end
