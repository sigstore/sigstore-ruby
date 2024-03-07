# frozen_string_literal: true

module Sigstore
  module Cosign
    module Verify
      module Policy
        class SingleX509ExtPolicy
          def initialize(value)
            @value = value
          end

          def verify(cert)
            ext = cert.find_extension(oid)
            unless ext
              return VerificationFailure.new("Certificate does not contain #{self.class.name&.[](/::([^:]+)$/, 1)} " \
                                             "(#{oid}) extension")
            end

            value = ext_value(ext)
            verified = value == @value
            unless verified
              return VerificationFailure.new("Certificate's #{self.class.name&.[](/::([^:]+)$/, 1)} does not match " \
                                             "(got #{value}, expected #{@value})")
            end

            VerificationSuccess.new
          end

          def ext_value(ext)
            ext.value
          end

          def oid
            self.class::OID # : String
          end
        end

        class OIDCIssuer < SingleX509ExtPolicy
          OID = "1.3.6.1.4.1.57264.1.1"
        end

        class OIDCIssuerV2 < SingleX509ExtPolicy
          OID = "1.3.6.1.4.1.57264.1.8"

          def ext_value(ext)
            OpenSSL::ASN1.decode(ext.value_der).value
          end
        end

        class AnyOf
          def initialize(*policies)
            @policies = policies
          end

          def verify(cert)
            failures = []
            @policies.each do |policy|
              result = policy.verify(cert)
              return result if result.verified?

              failures << result.reason
            end

            VerificationFailure.new("No policy matched: #{failures.join(", ")}")
          end
        end

        class Identity
          def initialize(identity:, issuer:)
            @identity = identity
            @issuer = AnyOf.new(OIDCIssuer.new(issuer), OIDCIssuerV2.new(issuer))
          end

          def verify(cert)
            issuer_verified = @issuer.verify(cert)
            return issuer_verified unless issuer_verified.verified?

            san_ext = cert.find_extension("subjectAltName")
            raise "Certificate does not contain subjectAltName extension" unless san_ext

            sequence = OpenSSL::ASN1.decode(san_ext.value_der)
            raise "subjectAltName is not a sequence" unless sequence.is_a?(OpenSSL::ASN1::Sequence)

            all_sans = sequence.map do |asn1_data|
              case asn1_data.tag
              when 6 # URI
                asn1_data.value
              else
                raise "Unknown SAN type: #{asn1_data.tag}"
              end
            end.compact

            verified = all_sans.include?(@identity)
            unless verified
              return VerificationFailure.new("Certificate's SANs do not match #{@identity}; actual SANs: #{all_sans}")
            end

            VerificationSuccess.new
          end
        end
      end
    end
  end
end
