# frozen_string_literal: true

require "test_helper"
require "sigstore/cosign/verify/models"
require "sigstore_protobuf_specs"

class Sigstore::Cosign::Verify::VerificationMaterialsTest < Test::Unit::TestCase
  def test_verification_materials_from_bundle
    json = File.read("test/sigstore-conformance/test/assets/a.txt.good.sigstore")
    bundle = Sigstore::Bundle::V1::Bundle.decode_json(json)
    materials = File.open("test/sigstore-conformance/test/assets/a.txt.good.sigstore", "rb") do |file|
      Sigstore::Cosign::Verify::VerificationMaterials.from_bundle(
        input: file,
        bundle: bundle,
        offline: true
      )
    end

    refute_nil(materials)
  end
end
