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

module Sigstore
  module Internal
    module X509
      class Certificate
        extend Forwardable

        attr_reader :openssl

        def initialize(x509_certificate)
          unless x509_certificate.is_a?(OpenSSL::X509::Certificate)
            raise ArgumentError,
                  "Invalid certificate: #{x509_certificate.inspect}"
          end

          @openssl = x509_certificate

          raise Error::InvalidCertificate, "invalid X.509 version: #{version.inspect}" if version != 2 # v3
        end

        def self.read(certificate_bytes)
          new(OpenSSL::X509::Certificate.new(certificate_bytes))
        end

        def tbs_certificate_der
          if openssl.respond_to?(:tbs_bytes)
            cert = openssl.dup
            short_name = Extension::PrecertificateSignedCertificateTimestamps.oid.short_name
            cert.extensions = cert.extensions.reject! do |ext|
              ext.oid == short_name
            end || raise(Error::InvalidCertificate,
                         "No PrecertificateSignedCertificateTimestamps found for the certificate")
            return cert.tbs_bytes
          end

          extension(Extension::PrecertificateSignedCertificateTimestamps) ||
            raise(Error::InvalidCertificate,
                  "No PrecertificateSignedCertificateTimestamps found for the certificate")

          # This uglyness is needed because there is no way to force modifying an X509 certificate
          # in a way that it will be serialized with the modifications.
          seq = OpenSSL::ASN1.decode(to_der)
          unless seq.is_a?(OpenSSL::ASN1::Sequence) && seq.value.size == 3
            raise Error::InvalidCertificate,
                  "invalid X.509 certificate: #{seq.class} #{seq.value.size}"
          end
          seq = seq.value[0]
          unless seq.is_a?(OpenSSL::ASN1::Sequence)
            raise Error::InvalidCertificate,
                  "invalid X.509 certificate: #{seq.inspect}"
          end

          seq.value = seq.value.map! do |v|
            next v unless v.tag == 3

            v.value = v.value.map! do |v2|
              v2.value = v2.value.map! do |v3|
                next if v3.first.oid == Extension::PrecertificateSignedCertificateTimestamps.oid.oid

                v3
              end.compact! || raise(Error::InvalidCertificate, "no SCTs found")
              v2
            end
            v
          end

          seq.to_der
        end

        def extension(cls)
          openssl.extensions.each do |ext|
            return cls.new(ext) if ext.oid == cls.oid || ext.oid == cls.oid.short_name
          end
          nil
        end

        def_delegators :openssl, :version, :not_after, :not_before, :to_pem, :to_der,
                       :public_key, :to_text

        def leaf?
          return false if ca?

          key_usage = extension(Extension::KeyUsage) ||
                      raise(Error::InvalidCertificate,
                            "no keyUsage in #{@x509_certificate.extensions.map(&:to_h)}")

          unless key_usage.digital_signature
            raise Error::InvalidCertificate,
                  "invalid certificate for Sigstore purposes: missing digital signature usage: #{key_usage.to_h}"
          end

          extended_key_usage = extension(Extension::ExtendedKeyUsage)
          return false unless extended_key_usage

          extended_key_usage.code_signing?
        end

        def ca?
          basic_constraints = extension(Extension::BasicConstraints)
          return false unless basic_constraints

          unless basic_constraints.critical?
            raise Error::InvalidCertificate,
                  "invalid X.509 certificate: non-critical BasicConstraints in CA"
          end

          key_usage = extension(Extension::KeyUsage)
          raise Error::InvalidCertificate, "no keyUsage in #{openssl.inspect}" unless key_usage

          ca = basic_constraints.ca
          key_cert_sign = key_usage.key_cert_sign

          return true if ca && key_cert_sign

          return false unless key_cert_sign || ca

          raise Error::InvalidCertificate,
                "invalid X.509 certificate: inconsistent CA/KeyCertSign in BasicConstraints/KeyUsage " \
                "(#{ca.inspect}, #{key_cert_sign.inspect}):" \
                "\n#{openssl.extensions.map(&:to_h).pretty_inspect}" \
                "\n#{key_usage.pretty_inspect}"
        end

        def preissuer?
          extended_key_usage = extension(Extension::ExtendedKeyUsage)
          return false unless extended_key_usage

          extended_key_usage.purposes.include?(OpenSSL::ASN1::ObjectId.new("1.3.6.1.4.1.11129.2.4.4"))
        end
      end

      class Extension
        class << self
          attr_accessor :oid, :schema
        end

        def initialize(extension)
          @extension = extension
          value = shift_value([OpenSSL::ASN1.decode(extension.to_der)], OpenSSL::ASN1::Sequence)
          @oid = value.shift

          unless @extension.is_a?(OpenSSL::X509::Extension) && @oid == self.class.oid
            raise ArgumentError,
                  "Invalid extension: #{@extension.inspect} is not a #{@oid.inspect}" \
                  "(#{self.class} / #{self.class.oid.inspect})"
          end

          @critical = false
          @critical = value.shift.value if value.first.is_a?(OpenSSL::ASN1::Boolean)
          raise ArgumentError, "Mis-parsed the critical bit" unless @critical == @extension.critical?

          contents = shift_value(value, OpenSSL::ASN1::OctetString)
          raise ArgumentError, "Invalid extension: extra fields left in #{self}: #{value}" unless value.empty?

          parse_value(OpenSSL::ASN1.decode(contents))
        end

        def critical?
          @extension.critical?
        end

        def shift_value(value, klass)
          v = value.shift
          raise ArgumentError, "Invalid extension: #{v} is not a #{klass}" unless v.is_a?(klass)

          v.value
        end

        def shift_bitstring(value)
          raise ArgumentError, "Invalid bit string: #{value.inspect}" unless value.is_a?(OpenSSL::ASN1::BitString)

          value.value.each_byte.flat_map do |byte|
            [byte & 0b1000_0000 != 0, byte & 0b0100_0000 != 0, byte & 0b0010_0000 != 0, byte & 0b0001_0000 != 0,
             byte & 0b0000_1000 != 0, byte & 0b0000_0100 != 0, byte & 0b0000_0010 != 0, byte & 0b0000_0001 != 0]
          end[..-value.unused_bits.succ]
        end

        class SubjectKeyIdentifier < Extension
          attr_reader :key_identifier

          self.oid = OpenSSL::ASN1::ObjectId.new("2.5.29.14")

          def parse_value(value)
            unless value.is_a?(OpenSSL::ASN1::OctetString)
              raise ArgumentError,
                    "Invalid key identifier: #{value.inspect}"
            end

            @key_identifier = value.value
          end
        end

        class KeyUsage < Extension
          self.oid = OpenSSL::ASN1::ObjectId.new("2.5.29.15")

          attr_reader :digital_signature, :non_repudiation, :key_encipherment, :data_encipherment, :key_agreement,
                      :key_cert_sign, :crl_sign, :encipher_only, :decipher_only

          def parse_value(value)
            @digital_signature, @non_repudiation, @key_encipherment, @data_encipherment, @key_agreement, @key_cert_sign,
            @crl_sign, @encipher_only, @decipher_only =
              shift_bitstring(value)
          end
        end

        class ExtendedKeyUsage < Extension
          self.oid = OpenSSL::ASN1::ObjectId.new("2.5.29.37")

          attr_reader :purposes

          def parse_value(value)
            unless value.is_a?(OpenSSL::ASN1::Sequence)
              rasie ArgumentError,
                    "Invalid extended key usage: #{value.inspect}"
            end

            @purposes = value.value
            return if @purposes.all? { |v| v.is_a?(OpenSSL::ASN1::ObjectId) }

            raise ArgumentError,
                  "Invalid extended key usage: #{value.inspect}"
          end

          CODE_SIGNING = OpenSSL::ASN1::ObjectId.new("1.3.6.1.5.5.7.3.3")

          def code_signing?
            purposes.any? { |oid| oid == CODE_SIGNING }
          end
        end

        class BasicConstraints < Extension
          self.oid = OpenSSL::ASN1::ObjectId.new("2.5.29.19")

          attr_reader :ca, :path_len_constraint

          def parse_value(value)
            value = shift_value([value], OpenSSL::ASN1::Sequence)

            @ca = false
            @path_len_constraint = nil

            @ca = shift_value(value, OpenSSL::ASN1::Boolean) if value.first.is_a?(OpenSSL::ASN1::Boolean)

            return unless value.first.is_a?(OpenSSL::ASN1::Integer)

            @path_len_constraint = shift_value(value, OpenSSL::ASN1::Integer)
          end
        end

        class SubjectAlternativeName < Extension
          self.oid = OpenSSL::ASN1::ObjectId.new("2.5.29.17")

          attr_reader :general_names

          #  id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

          #  SubjectAltName ::= GeneralNames

          #  GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

          #  GeneralName ::= CHOICE {
          #       otherName                       [0]     OtherName,
          #       rfc822Name                      [1]     IA5String,
          #       dNSName                         [2]     IA5String,
          #       x400Address                     [3]     ORAddress,
          #       directoryName                   [4]     Name,
          #       ediPartyName                    [5]     EDIPartyName,
          #       uniformResourceIdentifier       [6]     IA5String,
          #       iPAddress                       [7]     OCTET STRING,
          #       registeredID                    [8]     OBJECT IDENTIFIER }

          #  OtherName ::= SEQUENCE {
          #       type-id    OBJECT IDENTIFIER,
          #       value      [0] EXPLICIT ANY DEFINED BY type-id }

          #  EDIPartyName ::= SEQUENCE {
          #       nameAssigner            [0]     DirectoryString OPTIONAL,
          #       partyName               [1]     DirectoryString }

          def parse_value(value)
            value = shift_value([value], OpenSSL::ASN1::Sequence)

            @general_names = value.map do |general_name|
              tag = general_name.tag

              case tag
              when 6
                [:uniformResourceIdentifier, general_name.value]
              else
                raise Error::Unimplemented,
                      "Unhandled general name tag: #{tag}"
              end
            end
          end
        end

        class PrecertificateSignedCertificateTimestamps < Extension
          self.oid = OpenSSL::ASN1::ObjectId.new("1.3.6.1.4.1.11129.2.4.2")

          attr_reader :signed_certificate_timestamps

          def parse_value(value)
            unless value.is_a?(OpenSSL::ASN1::OctetString)
              raise ArgumentError,
                    "Invalid SCT extension: #{value.inspect}"
            end

            value = value.value
            length = value.unpack1("n")
            value = value.byteslice(2, length)

            unless value && value.bytesize == length
              raise Error::InvalidCertificate,
                    "decoding #{self.class.oid} extension"
            end

            length = value.unpack1("n")
            value = value.byteslice(2, length)

            unless value && value.bytesize == length
              raise Error::InvalidCertificate,
                    "decoding #{self.class.oid} extension"
            end

            @signed_certificate_timestamps = unpack_sct_list(value)
          end

          args = %i[version
                    log_id
                    timestamp
                    extensions_bytes
                    hash_algorithm
                    signature_algorithm
                    entry_type
                    signature]
          Timestamp = defined?(Data.define) ? Data.define(*args) : Struct.new(*args, keyword_init: true) # rubocop:disable Naming/ConstantName

          HASHES = {
            0 => "none",
            1 => "md5",
            2 => "sha1",
            3 => "sha224",
            4 => "sha256",
            5 => "sha384",
            6 => "sha512",
            255 => "unknown"
          }.freeze

          SIGNATURE_ALGORITHMS = {
            0 => "anonymous",
            1 => "rsa",
            2 => "dsa",
            3 => "ecdsa",
            255 => "unknown"
          }.freeze

          private

          if RUBY_VERSION >= "3.1"
            def unpack_at(string, format, offset:)
              string.unpack(format, offset: offset)
            end

            def unpack1_at(string, format, offset:)
              string.unpack1(format, offset: offset)
            end
          else
            def unpack_at(string, format, offset:)
              string[offset..].unpack(format)
            end

            def unpack1_at(string, format, offset:)
              string[offset..].unpack1(format)
            end
          end

          # https://letsencrypt.org/2018/04/04/sct-encoding.html
          def unpack_sct_list(string)
            offset = 0
            len = string.bytesize
            list = []
            while offset < len
              sct_version, sct_log_id, sct_timestamp, sct_extensions_len = unpack_at(string, "Ca32Q>n", offset: offset)
              offset += 1 + 32 + 8 + 2
              raise Error::Unimplemented, "expect sct version to be 0, got #{sct_version}" unless sct_version.zero?

              sct_extensions_bytes = unpack1_at(string, "a#{sct_extensions_len}", offset: offset).b
              offset += sct_extensions_len

              unless sct_extensions_len.zero?
                raise Error::Unimplemented,
                      "sct_extensions_len=#{sct_extensions_len} not supported"
              end

              sct_signature_alg_hash, sct_signature_alg_sign, sct_signature_len = unpack_at(string, "CCn",
                                                                                            offset: offset)
              offset += 1 + 1 + 2
              sct_signature_bytes = unpack1_at(string, "a#{sct_signature_len}", offset: offset).b
              offset += sct_signature_len
              list << Timestamp.new(
                version: sct_version,
                log_id: sct_log_id.unpack1("H*"),
                timestamp: sct_timestamp,
                hash_algorithm: HASHES.fetch(sct_signature_alg_hash),
                signature_algorithm: SIGNATURE_ALGORITHMS.fetch(sct_signature_alg_sign),
                signature: sct_signature_bytes,
                extensions_bytes: sct_extensions_bytes,
                entry_type: 1 # X509LogEntryType::PRECERTIFICATE
              )
            end
            raise Error::InvalidCertificate, "failed unpacking SCTs: offset=#{offset} len=#{len}" unless offset == len

            list
          end
        end
      end
    end
  end
end
