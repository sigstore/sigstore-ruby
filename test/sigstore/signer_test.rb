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
    stub_tsa(granted_timestamp_der)
    signer = Sigstore::Signer.allocate
    ts = signer.send(:request_timestamp, TSA_URL, "signature".b)
    assert_kind_of Sigstore::Common::V1::RFC3161SignedTimestamp, ts
    assert_equal granted_timestamp_der, ts.signed_timestamp
  end

  def test_request_timestamp_rejects_non_granted_status
    stub_tsa(status_only_timestamp_der(OpenSSL::Timestamp::Response::REJECTION))
    signer = Sigstore::Signer.allocate
    error = assert_raise(Sigstore::Error::InvalidTimestamp) do
      signer.send(:request_timestamp, TSA_URL, "signature".b)
    end
    assert_include error.message, "did not grant a timestamp"
  end

  def test_request_timestamp_rejects_malformed_response
    stub_tsa("not a valid DER timestamp response")
    signer = Sigstore::Signer.allocate
    assert_raise do
      signer.send(:request_timestamp, TSA_URL, "signature".b)
    end
  end
end
