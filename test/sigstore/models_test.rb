# frozen_string_literal: true

require "test_helper"
require "sigstore/models"
require "sigstore/trusted_root"

class Sigstore::BundleTypeTest < Test::Unit::TestCase
  def test_from_media_type
    assert_equal(Sigstore::BundleType::BUNDLE_0_1,
                 Sigstore::BundleType.from_media_type("application/vnd.dev.sigstore.bundle+json;version=0.1"))
    assert_equal(Sigstore::BundleType::BUNDLE_0_2,
                 Sigstore::BundleType.from_media_type("application/vnd.dev.sigstore.bundle+json;version=0.2"))
    assert_equal(Sigstore::BundleType::BUNDLE_0_3,
                 Sigstore::BundleType.from_media_type("application/vnd.dev.sigstore.bundle+json;version=0.3"))

    assert_raise(Sigstore::Error::InvalidBundle) do
      Sigstore::BundleType.from_media_type("application/vnd.dev.sigstore.bundle+json;version=0.0")
    end
  end

  def test_verification_input_no_bundle
    verification_input = Sigstore::Verification::V1::Input.new
    e = assert_raise(ArgumentError) { Sigstore::VerificationInput.new(verification_input) }
    assert_equal("bundle must be a Sigstore::Bundle::V1::Bundle, is NilClass", e.message)
  end

  def test_verification_input_bundle_missing_media_type
    verification_input = Sigstore::Verification::V1::Input.new
    verification_input.bundle = Sigstore::Bundle::V1::Bundle.new
    e = assert_raise(Sigstore::Error::InvalidBundle) { Sigstore::VerificationInput.new(verification_input) }
    assert_equal("Unsupported bundle format: \"\"", e.message)
  end

  def test_verification_input_bundle_missing_verification_material
    verification_input = Sigstore::Verification::V1::Input.new
    verification_input.bundle = Sigstore::Bundle::V1::Bundle.new
    verification_input.bundle.media_type = Sigstore::BundleType::BUNDLE_0_3.media_type
    e = assert_raise(Sigstore::Error::InvalidBundle) { Sigstore::VerificationInput.new(verification_input) }
    assert_equal("bundle requires verification material", e.message)
  end
end
