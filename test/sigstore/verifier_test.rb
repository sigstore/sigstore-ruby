# frozen_string_literal: true

require "test_helper"
require "sigstore/verifier"

class Sigstore::VerifierTest < Test::Unit::TestCase
  def test_tbs_certificate_der
    certificate = Sigstore::Internal::X509::Certificate.read(File.binread(File.join(__dir__,
                                                                                    "data/x509/cryptography-scts.pem")))
    expected = File.binread(File.join(__dir__, "data/x509/cryptography-scts-tbs-precert.der"))

    verifier = Sigstore::Verifier.allocate
    actual = verifier.send(:tbs_certificate_der, certificate)
    assert_equal(expected, actual)
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
      verifier.singleton_class.send(:undef_method, :tbs_certificate_der)
      verifier.singleton_class.send(:define_method, :tbs_certificate_der) { |_| precert_bytes }
      data = verifier.send(:pack_digitally_signed, sct, nil, issuer_key_id)
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
