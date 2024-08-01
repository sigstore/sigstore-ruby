# frozen_string_literal: true

require "test_helper"
require "sigstore/models"
require "sigstore/trusted_root"

class Sigstore::VerificationMaterialsTest < Test::Unit::TestCase
  def test_verification_materials_from_bundle
    json = File.read("test/sigstore-conformance/test/assets/a.txt.good.sigstore.json")
    bundle = Sigstore::Bundle::V1::Bundle.decode_json(json, registry: Sigstore::REGISTRY)
    materials = File.open("test/sigstore-conformance/test/assets/a.txt.good.sigstore.json", "rb") do |file|
      Sigstore::VerificationMaterials.from_bundle(
        input: file,
        bundle: bundle,
        offline: false
      )
    end

    refute_nil(materials)
  end

  def test_offline_verification_requires_rekor_entry
    assert_raise(ArgumentError) do
      Sigstore::VerificationMaterials.new(
        input: StringIO.new(""),
        rekor_entry: nil
      )
    end
  end
end

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
