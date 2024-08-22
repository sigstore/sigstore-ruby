# frozen_string_literal: true

# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require_relative "internal/util"
require_relative "internal/x509"
require_relative "models"
require_relative "policy"
require_relative "verifier"

module Sigstore
  class Signer
    include Loggable

    def initialize(jwt:, trusted_root:)
      @jwt = jwt
      @trusted_root = trusted_root
    end

    def sign(payload)
      # 2) generate a keypair
      keypair = generate_keypair
      # 3) generate a CreateSigningCertificateRequest
      csr = generate_csr(keypair)
      # 4) get a cert chain from fulcio
      chain = fetch_cert(csr)
      # 5) verify returned cert chain
      leaf, _chain = verify_chain(chain)
      # 6) sign the payload
      signature = sign_payload(payload, keypair)
      # 7) send hash of signature to timestamping service
      timestamp_verification_data = submit_signature_hash_to_timstamping_service(signature)
      # 8) submit signed metadata to transparency service
      hashed_input = Common::V1::HashOutput.new
      hashed_input.algorithm = Common::V1::HashAlgorithm::SHA2_256
      hashed_input.digest = OpenSSL::Digest("SHA256").digest(payload)
      tlog_entries = submit_signed_metadata_to_transparency_service(signature, leaf,
                                                                    hashed_input.digest)
      # 9) perform verification

      bundle = collect_bundle(leaf, tlog_entries, timestamp_verification_data, hashed_input, signature)
      verify(payload, bundle)

      bundle
    end

    private

    def generate_keypair
      # TODO: check if the type of key matters?
      # maybe allow configuring?
      key = OpenSSL::PKey::EC.generate("prime256v1")
      logger.debug { "Generated keypair #{key}" }
      key
    end

    def generate_csr(keypair)
      csr = OpenSSL::X509::Request.new

      csr.version = 0 # TODO: check
      # TODO: proper name
      # The subject in the CertificationRequestInfo is an X.501 RelativeDistinguishedName.
      # The value of the RelativeDistinguishedName SHOULD be the subject of the authentication token;
      # its type MUST be the type identified in the Fulcio instance’s public configuration.
      csr.subject = OpenSSL::X509::Name.new [%w[CN noone], %w[DC example]]
      csr.public_key = keypair
      # TODO: digest from trusted root config
      csr.sign keypair, "SHA256"

      {
        credentials: {
          oidc_identity_token: @jwt
        },
        certificate_signing_request: Internal::Util.base64_encode(csr.to_pem)
      }
    end

    def fetch_cert(csr)
      uri = URI.parse @trusted_root.certificate_authority_for_signing.uri
      uri = URI.join(uri, "api/v2/signingCert")
      resp = Net::HTTP.post(
        uri,
        JSON.dump(csr),
        { "Content-Type" => "application/json" }
      )

      unless resp.code == "200"
        raise Error::Signing,
              "#{resp.code} #{resp.message}\n\n#{Internal::Util.base64_encode JSON.dump(csr)}\n\n#{resp.body}"
      end

      resp_body = JSON.parse(resp.body)

      chain = resp_body.fetch("signedCertificateEmbeddedSct").fetch("chain")
                       .fetch("certificates").map { |pem| Internal::X509::Certificate.read(pem) }
      logger.debug { "Fetched cert from fulcio" }
      chain
    end

    def verify_chain(chain)
      # Perform certification path validation (RFC 5280 §6) of the returned certificate chain with the pre-distributed
      # Fulcio root certificate(s) as a trust anchor.

      x509_store = OpenSSL::X509::Store.new
      chain = chain.map(&:openssl)
      leaf = chain.shift
      root = chain.pop # TODO: use root from trusted root as trust anchor
      x509_store.add_cert root
      raise x509_store.error_string unless x509_store.verify(leaf, chain)

      logger.debug { "verified chain" }

      # TODO: verify SCT in leaf
      # Extract a SignedCertificateTimestamp, which may be embedded as an X.509 extension in the leaf certificate or
      # attached separately in the SigningCertificate returned from the Identity Service.
      # Verify this SignedCertificateTimestamp as in RFC 9162 §8.1.3, using the root certificate from
      # the Certificate Transparency Log.

      # TODO: verify leaf subject
      # Check that the leaf certificate contains the subject from the certificate signing request and encodes the
      # appropriate AuthenticationServiceIdentifier in an extension with OID 1.3.6.1.4.1.57264.1.8.

      [leaf, x509_store.chain]
    end

    def sign_payload(payload, key)
      # TODO: derive correct digest from what the registry supports
      # The Signer MAY pre-hash the payload using a hash algorithm from the registry (Spec: Sigstore Registries) for
      # compatibility with some signing metadata formats (see §Submission of Signing Metadata to Transparency Service).
      key.sign("SHA256", payload)
    end

    # TODO: implement
    def submit_signature_hash_to_timstamping_service(_signature)
      # The Signer sends a hash of the signature as the messageImprint in a TimeStampReq to the Timestamping Service and
      # receives a TimeStampResp including a `TimeStampToken`.
      # The signer MUST verify the TimeStampToken against the payload and Timestamping Service root certificate.

      nil
    end

    def submit_signed_metadata_to_transparency_service(signature, cert, data_sha256)
      # The Signer chooses a format for signing metadata; this format MUST be in the supportedMetadataFormats in the
      # Transparency Service configuration. The Signer prepares signing metadata containing at a minimum:
      # * The signature.
      # * The payload (possibly pre-hashed; if so, the entry also includes the identifier of the hash algorithm).
      # * Verification material (signing certificate or verification key).
      #   * If the verification material is a certificate, the client SHOULD upload only the signing certificate and
      #     SHOULD NOT upload the CA certificate chain.
      #
      # The signing metadata might contain additional, application-specific metadata according to the format used.
      # The Signer then canonically encodes the metadata (according to the chosen format).

      # TODO: is looping here correct?
      @trusted_root.tlogs_for_signing.map do |ctlog|
        logger.info { "Submitting to #{ctlog.base_url}" }

        body = {
          "spec" => {
            "signature" => {
              "content" => Internal::Util.base64_encode(signature),
              "publicKey" => {
                "content" => Internal::Util.base64_encode(cert.to_pem)
              }
            },
            "data" => {
              "hash" => {
                "algorithm" => "sha256", # TODO: should this always be sha256?
                "value" => Internal::Util.hex_encode(data_sha256)
              }
            }
          },
          "kind" => "hashedrekord", # TODO: is hashedrekord always the right kind? should this be configurable?
          "apiVersion" => "0.0.1"
        }

        # TODO: verify
        # The signer MUST verify the log entry as in Spec: Transparency Service.
        Rekor::Client.for_trust_root(url: ctlog.base_url, trust_root: @trusted_root)
                     .log.entries.post(body)
      end
    end

    def verify(artifact, bundle)
      verifier = Verifier.for_trust_root(rekor_url: @trusted_root.tlogs_for_signing.first.base_url,
                                         trust_root: @trusted_root)

      verification_input = Verification::V1::Input.new
      verification_input.bundle = bundle
      verification_input.artifact = Verification::V1::Artifact.new
      verification_input.artifact.artifact = artifact

      result = verifier.verify(
        input: VerificationInput.new(verification_input),
        policy: expected_identity,
        offline: false
      )
      raise Error::Signing, "Failed to verify: #{result.reason}" unless result.verified?
    end

    class NullVerifier
      def verify(_cert)
        VerificationSuccess.new
      end
    end

    def expected_identity
      _header, claims, _sig = @jwt.split(".").map { |d| d.unpack1("m*") }

      claims = JSON.parse(claims)
      issuer = claims["iss"]
      identity = claims["sub"] # TODO: this isn't the correct identity for GHA tokens

      Policy::Identity.new(identity: identity, issuer: issuer)
      NullVerifier.new # TODO: expect the real identity
    end

    def collect_bundle(leaf_certificate, tlog_entries, timestamp_verification_data, hashed_input, signature)
      bundle = Bundle::V1::Bundle.new
      bundle.media_type = BundleType::BUNDLE_0_3.media_type
      bundle.verification_material = Bundle::V1::VerificationMaterial.new
      bundle.verification_material.certificate = Common::V1::X509Certificate.new
      bundle.verification_material.certificate.raw_bytes = leaf_certificate.to_pem
      bundle.verification_material.tlog_entries = tlog_entries
      bundle.verification_material.timestamp_verification_data = timestamp_verification_data
      bundle.message_signature = Sigstore::Common::V1::MessageSignature.new.tap do |ms|
        ms.message_digest = hashed_input
        ms.signature = signature
      end
      bundle
    end
  end
end
