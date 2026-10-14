# frozen_string_literal: true

require "test_helper"
require "sigstore/signer"

class Sigstore::SignerTest < Test::Unit::TestCase
  TSA_URL = "https://tsa.example/api/v1/timestamp"

  # A real, granted RFC 3161 timestamp token taken from the rekor2 happy-path bundle.
  def granted_timestamp_der
    bundle = JSON.parse(
      Gem.read_binary("test/sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json")
    )
    encoded = bundle.dig("verificationMaterial", "timestampVerificationData", "rfc3161Timestamps", 0,
                         "signedTimestamp")
    encoded.unpack1("m")
  end

  # A minimal TimeStampResp whose PKIStatus is `status` and which carries no token.
  def status_only_timestamp_der(status)
    OpenSSL::ASN1::Sequence.new(
      [OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(status)])]
    ).to_der
  end

  def stub_tsa(body)
    stub_request(:post, TSA_URL)
      .to_return(status: 200, body:, headers: { "Content-Type" => "application/timestamp-reply" })
  end

  def test_request_timestamp_accepts_granted_response
    omit_if(!defined?(OpenSSL::Timestamp), "OpenSSL::Timestamp is unavailable (e.g. JRuby)")
    stub_tsa(granted_timestamp_der)
    signer = Sigstore::Signer.allocate
    ts = signer.send(:request_timestamp, TSA_URL, "signature".b)
    assert_kind_of Sigstore::Common::V1::RFC3161SignedTimestamp, ts
    assert_equal granted_timestamp_der, ts.signed_timestamp
  end

  def test_request_timestamp_rejects_non_granted_status
    omit_if(!defined?(OpenSSL::Timestamp), "OpenSSL::Timestamp is unavailable (e.g. JRuby)")
    stub_tsa(status_only_timestamp_der(OpenSSL::Timestamp::Response::REJECTION))
    signer = Sigstore::Signer.allocate
    error = assert_raise(Sigstore::Error::InvalidTimestamp) do
      signer.send(:request_timestamp, TSA_URL, "signature".b)
    end
    assert_include error.message, "did not grant a timestamp"
  end

  def test_request_timestamp_rejects_malformed_response
    omit_if(!defined?(OpenSSL::Timestamp), "OpenSSL::Timestamp is unavailable (e.g. JRuby)")
    stub_tsa("not a valid DER timestamp response")
    signer = Sigstore::Signer.allocate
    assert_raise do
      signer.send(:request_timestamp, TSA_URL, "signature".b)
    end
  end

  STATEMENT = '{"_type":"https://in-toto.io/Statement/v1","subject":[]}'

  def leaf_certificate
    bundle = JSON.parse(
      Gem.read_binary("test/sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json")
    )
    raw = bundle.dig("verificationMaterial", "certificate", "rawBytes").unpack1("m")
    Sigstore::Internal::X509::Certificate.read(raw)
  end

  def test_build_dsse_envelope
    signer = Sigstore::Signer.allocate
    envelope = signer.send(:build_dsse_envelope, STATEMENT, Sigstore::Signer::IN_TOTO_PAYLOAD_TYPE, "RAWSIG".b)

    assert_equal STATEMENT, envelope.payload
    assert_equal "application/vnd.in-toto+json", envelope.payloadType
    assert_equal ["RAWSIG"], envelope.signatures.map(&:sig)
  end

  def test_build_proposed_dsse_entry_is_a_v1_dsse_entry
    signer = Sigstore::Signer.allocate
    envelope = signer.send(:build_dsse_envelope, STATEMENT, Sigstore::Signer::IN_TOTO_PAYLOAD_TYPE, "RAWSIG".b)
    entry = signer.send(:build_proposed_dsse_entry, envelope, leaf_certificate)

    assert_equal "dsse", entry["kind"]
    assert_equal "0.0.1", entry["apiVersion"]
    # The envelope is nested as a JSON string whose payload round-trips.
    nested = JSON.parse(entry.dig("spec", "proposedContent", "envelope"))
    assert_equal STATEMENT, nested["payload"].unpack1("m0")
    verifiers = entry.dig("spec", "proposedContent", "verifiers")
    assert_equal([leaf_certificate.to_pem], verifiers.map { |v| v.unpack1("m0") })
  end

  # Rekor v2 stores a DSSE envelope as a hashedrekord over the PAE digest.
  def test_dsse_rekor_v2_request_digests_the_pae
    signer = Sigstore::Signer.allocate
    pae = Sigstore::Internal::Util.dsse_pae(Sigstore::Signer::IN_TOTO_PAYLOAD_TYPE, STATEMENT)
    request = signer.send(:build_create_entry_request, OpenSSL::Digest::SHA256.digest(pae), "RAWSIG".b,
                          leaf_certificate)

    spec = request.fetch("hashedRekordRequestV002")
    assert_equal OpenSSL::Digest::SHA256.digest(pae), spec.fetch("digest").unpack1("m0")
    assert_equal "RAWSIG", spec.dig("signature", "content").unpack1("m0")
    assert_equal "PKIX_ECDSA_P256_SHA_256", spec.dig("signature", "verifier", "keyDetails")
  end
end
