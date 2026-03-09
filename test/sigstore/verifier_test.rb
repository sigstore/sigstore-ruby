# frozen_string_literal: true

require "test_helper"
require "sigstore/verifier"

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
