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
end
