# frozen_string_literal: true

require "test_helper"
require "sigstore/version"

class Sigstore::VersionTest < Test::Unit::TestCase
  def test_version
    assert_instance_of String, Sigstore::VERSION
  end
end
