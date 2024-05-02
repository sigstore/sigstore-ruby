# frozen_string_literal: true

require "test_helper"

require "sigstore/internal/x509"

class Sigstore::Internal::X509::CertificateTest < Test::Unit::TestCase
  def test_cert
    cert = Sigstore::Internal::X509::Certificate.new(
      OpenSSL::X509::Certificate.new(File.binread(File.join(__dir__, "../data/x509/cryptography-scts.pem")))
    )
    refute_nil(cert)

    refute_nil(ext = cert.extension(Sigstore::Internal::X509::Extension::SubjectKeyIdentifier))
    assert_equal("\x8D\xB7\xB4lMZg\xC1\xE2\xAA\xDC*Q\xF0\x9E\xD7\x96\xC5W\xC5".b, ext.key_identifier)

    refute_nil(ext = cert.extension(Sigstore::Internal::X509::Extension::KeyUsage))
    assert_predicate ext, :digital_signature
    refute_predicate ext, :key_cert_sign

    refute_nil(ext = cert.extension(Sigstore::Internal::X509::Extension::ExtendedKeyUsage))
    assert_equal(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"], ext.purposes.map(&:oid))

    refute_nil(ext = cert.extension(Sigstore::Internal::X509::Extension::BasicConstraints))
    refute_predicate ext, :ca
    assert_nil ext.path_len_constraint

    refute_nil(ext = cert.extension(Sigstore::Internal::X509::Extension::PrecertificateSignedCertificateTimestamps))
    assert_equal([
                   { entry_type: 1,
                     extensions_bytes: "",
                     hash_algorithm: "sha256",
                     log_id: "293c519654c83965baaa50fc5807d4b76fbf587a2972dca4c30cf4e54547f478",
                     signature: "0F\x02!\x00\xA5\xCE\xA8|Pnq\x8C&\xE3H\xBB\xF4\v\xC1\x0Eu\xE8M}\xE6:\x8BM\x1E~\x89\n" \
                                "r\xDA\xA4@\x02!\x00\xDE\xA9\xF1\xD0\xC3S\xFC\xD37\xE1[q_\x80(\x85u\x80]Kw\x02\xC0'" \
                                "\x02\xEE\xD8\xF7\x15N|r".b,
                     signature_algorithm: "ecdsa",
                     timestamp: 1_537_995_393_769,
                     version: 0 }
                 ],
                 ext.signed_certificate_timestamps.map(&:to_h))
  end
end
