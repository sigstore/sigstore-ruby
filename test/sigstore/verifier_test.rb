# frozen_string_literal: true

require "test_helper"
require "sigstore/verifier"
require "sigstore/models"

class Sigstore::VerifierTest < Test::Unit::TestCase
  HEXDIGEST256 = "01234567" * 8
  OTHER_HEXDIGEST256 = "0" * 64

  HashedInput = Struct.new(:hashed_input)

  def make_input(hexdigest)
    digest = [hexdigest].pack("H*")
    hashed_input = Sigstore::Common::V1::HashOutput.new
    hashed_input.algorithm = Sigstore::Common::V1::HashAlgorithm::SHA2_256
    hashed_input.digest = digest
    HashedInput.new(hashed_input)
  end

  def make_payload(subjects)
    {
      "_type" => "https://in-toto.io/Statement/v1",
      "subject" => subjects,
      "predicateType" => "https://slsa.dev/provenance/v1",
      "predicate" => {}
    }
  end

  def test_verify_in_toto_single_subject_matches
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([
                             { "name" => "artifact.txt", "digest" => { "sha256" => HEXDIGEST256 } }
                           ])
    assert_nil verifier.send(:verify_in_toto, input, payload)
  end

  def test_verify_in_toto_multiple_subjects_first_matches
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([
                             { "name" => "artifact.txt", "digest" => { "sha256" => HEXDIGEST256 } },
                             { "name" => "other.txt", "digest" => { "sha256" => OTHER_HEXDIGEST256 } }
                           ])
    assert_nil verifier.send(:verify_in_toto, input, payload)
  end

  def test_verify_in_toto_multiple_subjects_second_matches
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([
                             { "name" => "other.txt", "digest" => { "sha256" => OTHER_HEXDIGEST256 } },
                             { "name" => "artifact.txt", "digest" => { "sha256" => HEXDIGEST256 } }
                           ])
    assert_nil verifier.send(:verify_in_toto, input, payload)
  end

  def test_verify_in_toto_no_subject_matches
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([
                             { "name" => "other.txt", "digest" => { "sha256" => OTHER_HEXDIGEST256 } }
                           ])
    result = verifier.send(:verify_in_toto, input, payload)
    assert_kind_of Sigstore::VerificationFailure, result
  end

  def test_verify_in_toto_wrong_algorithm_does_not_match
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([
                             { "name" => "artifact.txt", "digest" => { "sha512_256" => HEXDIGEST256 } }
                           ])
    result = verifier.send(:verify_in_toto, input, payload)
    assert_kind_of Sigstore::VerificationFailure, result
  end

  def test_verify_in_toto_no_subjects_raises
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload(nil)
    assert_raise Sigstore::Error::InvalidBundle do
      verifier.send(:verify_in_toto, input, payload)
    end
  end

  def test_verify_in_toto_empty_subjects_raises
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([])
    assert_raise Sigstore::Error::InvalidBundle do
      verifier.send(:verify_in_toto, input, payload)
    end
  end

  def test_verify_in_toto_no_digest_raises
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([{ "name" => "artifact.txt" }])
    assert_raise Sigstore::Error::InvalidBundle do
      verifier.send(:verify_in_toto, input, payload)
    end
  end

  def test_verify_in_toto_empty_digest_raises
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([{ "name" => "artifact.txt", "digest" => {} }])
    assert_raise Sigstore::Error::InvalidBundle do
      verifier.send(:verify_in_toto, input, payload)
    end
  end

  def test_verify_in_toto_wrong_type_raises
    verifier = Sigstore::Verifier.allocate
    input = make_input(HEXDIGEST256)
    payload = make_payload([
                             { "name" => "artifact.txt", "digest" => { "sha256" => HEXDIGEST256 } }
                           ])
    payload["_type"] = "https://in-toto.io/Statement/v0.1"
    assert_raise Sigstore::Error::InvalidBundle do
      verifier.send(:verify_in_toto, input, payload)
    end
  end

  # ---------------------------------------------------------------------------
  # Rekor v2 (hashedrekord 0.0.2) consistency checks.
  #
  # These drive the real message-signature happy-path bundle (which carries a v2
  # entry) so the leaf certificate, signature, and canonicalized body are genuine,
  # then mutate copies of the parsed body to exercise each rejection branch of
  # Verifier#verify_rekor_v2_entry_consistency offline (no network, no key checks).
  # ---------------------------------------------------------------------------

  REKOR2_DIR = "test/sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path"
  REKOR2_ARTIFACT = "test/sigstore-conformance/test/assets/bundle-verify/a.txt"

  def rekor2_bundle
    bytes = Gem.read_binary("#{REKOR2_DIR}/bundle.sigstore.json")
    Sigstore::SBundle.new(Sigstore::Bundle::V1::Bundle.decode_json(bytes, registry: Sigstore::REGISTRY))
  end

  def rekor2_hashed_input
    Sigstore::Common::V1::HashOutput.new.tap do |h|
      h.algorithm = Sigstore::Common::V1::HashAlgorithm::SHA2_256
      h.digest = OpenSSL::Digest.new("SHA256").digest(Gem.read_binary(REKOR2_ARTIFACT))
    end
  end

  # The genuine parsed v2 body for the happy-path bundle.
  def rekor2_body(bundle = rekor2_bundle)
    JSON.parse(bundle.verification_material.tlog_entries.first.canonicalized_body)
  end

  def assert_rekor2_consistency_raises(message_match, bundle: rekor2_bundle)
    body = rekor2_body(bundle)
    yield body if block_given?
    verifier = Sigstore::Verifier.allocate
    error = assert_raise(Sigstore::Error::InvalidRekorEntry) do
      verifier.send(:verify_rekor_v2_entry_consistency, bundle, rekor2_hashed_input, body)
    end
    assert_include error.message, message_match
  end

  def test_rekor_v2_consistency_accepts_genuine_entry
    verifier = Sigstore::Verifier.allocate
    assert_nothing_raised do
      verifier.send(:verify_rekor_v2_entry_consistency, rekor2_bundle, rekor2_hashed_input, rekor2_body)
    end
  end

  def test_rekor_v2_consistency_rejects_missing_spec
    assert_rekor2_consistency_raises("missing hashedRekordV002 spec") do |body|
      body["spec"].delete("hashedRekordV002")
    end
  end

  def test_rekor_v2_consistency_rejects_cert_mismatch
    other_cert = Sigstore::Internal::Util.base64_encode("not the bundle certificate")
    assert_rekor2_consistency_raises("certificate does not match") do |body|
      body["spec"]["hashedRekordV002"]["signature"]["verifier"]["x509Certificate"]["rawBytes"] = other_cert
    end
  end

  def test_rekor_v2_consistency_rejects_algorithm_mismatch
    assert_rekor2_consistency_raises("data algorithm") do |body|
      body["spec"]["hashedRekordV002"]["data"]["algorithm"] = "SHA2_512"
    end
  end

  def test_rekor_v2_consistency_rejects_digest_mismatch
    other_digest = Sigstore::Internal::Util.base64_encode("0" * 32)
    assert_rekor2_consistency_raises("data digest does not match") do |body|
      body["spec"]["hashedRekordV002"]["data"]["digest"] = other_digest
    end
  end

  def test_rekor_v2_consistency_rejects_signature_mismatch
    other_sig = Sigstore::Internal::Util.base64_encode("not the bundle signature")
    assert_rekor2_consistency_raises("signature does not match") do |body|
      body["spec"]["hashedRekordV002"]["signature"]["content"] = other_sig
    end
  end

  def test_rekor_v2_consistency_rejects_invalid_base64_digest
    assert_rekor2_consistency_raises("invalid base64 in data.digest") do |body|
      body["spec"]["hashedRekordV002"]["data"]["digest"] = "!!!not base64!!!"
    end
  end

  def test_rekor_v2_consistency_rejects_missing_digest_field
    assert_rekor2_consistency_raises("missing data.digest") do |body|
      body["spec"]["hashedRekordV002"]["data"].delete("digest")
    end
  end

  def test_rekor_v2_expected_data_dsse_requires_single_signature
    # The "exactly one DSSE signature" guard lives in the expected-data helper that the
    # consistency check calls; drive it directly with a DSSE bundle carrying two sigs.
    bundle = rekor2_dsse_bundle_with_two_signatures
    verifier = Sigstore::Verifier.allocate
    error = assert_raise(Sigstore::Error::InvalidRekorEntry) do
      verifier.send(:rekor_v2_expected_data_and_signature, bundle, rekor2_hashed_input)
    end
    assert_include error.message, "exactly one DSSE signature"
  end

  def rekor2_dsse_bundle_with_two_signatures
    dir = "test/sigstore-conformance/test/assets/bundle-verify/rekor2-dsse-happy-path"
    bytes = Gem.read_binary("#{dir}/bundle.sigstore.json")
    bundle = Sigstore::Bundle::V1::Bundle.decode_json(bytes, registry: Sigstore::REGISTRY)
    extra = bundle.dsse_envelope.signatures.first.class.new.tap { |s| s.sig = "second signature".b }
    bundle.dsse_envelope.signatures = bundle.dsse_envelope.signatures + [extra]
    Sigstore::SBundle.new(bundle)
  end

  # ---------------------------------------------------------------------------
  # rekor_v2_body: only hashedrekord 0.0.2 JSON bodies are treated as v2.
  # ---------------------------------------------------------------------------

  FakeEntry = Struct.new(:canonicalized_body)

  def test_rekor_v2_body_returns_body_for_v2_entry
    verifier = Sigstore::Verifier.allocate
    body = verifier.send(:rekor_v2_body, rekor2_bundle.verification_material.tlog_entries.first)
    assert_equal %w[hashedrekord 0.0.2], body.values_at("kind", "apiVersion")
  end

  def test_rekor_v2_body_nil_for_non_json
    verifier = Sigstore::Verifier.allocate
    assert_nil verifier.send(:rekor_v2_body, FakeEntry.new("not json"))
  end

  def test_rekor_v2_body_nil_for_non_v2_kind_version
    verifier = Sigstore::Verifier.allocate
    body = JSON.dump("kind" => "hashedrekord", "apiVersion" => "0.0.1")
    assert_nil verifier.send(:rekor_v2_body, FakeEntry.new(body))
  end

  # ---------------------------------------------------------------------------
  # decode_base64_field
  # ---------------------------------------------------------------------------

  def test_decode_base64_field_decodes_valid_value
    verifier = Sigstore::Verifier.allocate
    encoded = Sigstore::Internal::Util.base64_encode("hello")
    assert_equal "hello", verifier.send(:decode_base64_field, encoded, "field")
  end

  def test_decode_base64_field_raises_on_missing
    verifier = Sigstore::Verifier.allocate
    error = assert_raise(Sigstore::Error::InvalidRekorEntry) do
      verifier.send(:decode_base64_field, nil, "data.digest")
    end
    assert_include error.message, "missing data.digest"
  end

  def test_decode_base64_field_raises_on_invalid_base64
    verifier = Sigstore::Verifier.allocate
    error = assert_raise(Sigstore::Error::InvalidRekorEntry) do
      verifier.send(:decode_base64_field, "!!!not base64!!!", "data.digest")
    end
    assert_include error.message, "invalid base64 in data.digest"
  end

  def test_pack_digitally_signed_precertificate
    verifier = Sigstore::Verifier.allocate
    [3, 255, 1024, 16_777_215].each do |precert_bytes_len|
      precert_bytes = "x".b * precert_bytes_len
      sct = Sigstore::Internal::X509::Extension::PrecertificateSignedCertificateTimestamps::Timestamp.new(
        log_id: nil,
        extensions_bytes: nil,
        hash_algorithm: nil,
        signature_algorithm: nil,
        signature: nil,

        version: 0,
        timestamp: 1234,
        entry_type: 1
      )
      issuer_key_id = "iamapublickeyshatwofivesixdigest"
      cert = Sigstore::Internal::X509::Certificate.allocate
      cert.singleton_class.send(:define_method, :tbs_certificate_der) { precert_bytes }
      data = verifier.send(:pack_digitally_signed, sct, cert, issuer_key_id)
      _, l1, l2, l3 = [precert_bytes.bytesize].pack("N").unpack("C4")
      assert_equal [
        "\x00", # version
        "\x00", # signature_type
        "\x00\x00\x00\x00\x00\x00\x04\xD2", # timestamp
        "\x00\x01", # entry_type
        issuer_key_id,
        l1.chr, l2.chr, l3.chr, # tbs cert len
        precert_bytes,
        "\x00\x00", # extensions length
        "" # extensions
      ].map!(&:b).join, data, "precert_bytes_len=#{precert_bytes_len}"
    end
  end
end
