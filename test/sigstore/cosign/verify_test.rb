# frozen_string_literal: true

require "test_helper"

class Sigstore::Cosign::VerifyTest < Test::Unit::TestCase
  test "VERSION" do
    assert do
      ::Sigstore::Cosign::Verify.const_defined?(:VERSION)
    end
  end
end
