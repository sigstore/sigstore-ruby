# frozen_string_literal: true

require "test_helper"

class Sigstore::Cosign::Verify::VersionTest < Test::Unit::TestCase
  def test_version
    assert_instance_of String, Sigstore::Cosign::Verify::VERSION
  end
end
