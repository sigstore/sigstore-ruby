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

require_relative "util"

module Sigstore
  module Internal
    class Key
      include Loggable

      def self.from_key_details(key_details, key_bytes)
        case key_details
        when Common::V1::PublicKeyDetails::PKIX_ECDSA_P256_SHA_256
          key_type = "ecdsa"
          key_schema = "ecdsa-sha2-nistp256"
        when Common::V1::PublicKeyDetails::PKCS1_RSA_PKCS1V5
          key_type = "rsa"
          key_schema = "rsa-pkcs1v15-sha256"
        else
          # Skip unrecognized key types instead of raising an error.
          # This allows the library to work with newer trusted roots that include
          # key types we don't yet support (e.g., PKIX_ED25519 for Rekor v2).
          logger.warn { "Skipping unrecognized key type: #{key_details}" }
          return nil
        end

        read(key_type, key_schema, key_bytes, key_id: OpenSSL::Digest::SHA256.hexdigest(key_bytes))
      end

      def self.read(key_type, schema, key_bytes, key_id: nil)
        case key_type
        when "ecdsa", "ecdsa-sha2-nistp256"
          pkey = OpenSSL::PKey::EC.new(key_bytes)
          EDCSA.new(key_type, schema, pkey, key_id:)
        when "ed25519"
          pkey = ED25519.pkey_from_der([key_bytes].pack("H*"))
          ED25519.new(key_type, schema, pkey, key_id:)
        when "rsa"
          pkey = OpenSSL::PKey::RSA.new(key_bytes)
          RSA.new(key_type, schema, pkey, key_id:)
        else
          raise ArgumentError, "Unsupported key type #{key_type}"
        end
      rescue OpenSSL::PKey::PKeyError => e
        raise OpenSSL::PKey::PKeyError, "Invalid key: #{e} for #{key_type} #{schema} #{key_id}"
      end

      attr_reader :key_type, :schema, :key_id

      def initialize(key_type, schema, key, key_id: nil)
        @key_type = key_type
        @key = key
        @schema = schema
        @key_id = key_id
      end

      def to_pem
        @key.to_pem
      end

      def to_der
        @key.to_der
      end

      def verify(algo, signature, data)
        @key.verify(algo, signature, data)
      rescue OpenSSL::PKey::PKeyError => e
        logger.debug { "Verification failed: #{e}" }
        false
      end

      def public_to_der
        @key.public_to_der
      end

      class EDCSA < Key
        def initialize(...)
          super
          unless @key_type == "ecdsa" || @key_type == "ecdsa-sha2-nistp256"
            raise ArgumentError,
                  "key_type must be edcsa, given #{@key_type}"
          end
          unless @key.is_a?(OpenSSL::PKey::EC)
            raise ArgumentError,
                  "key must be an OpenSSL::PKey::EC, is #{@key.inspect}"
          end

          case @schema
          when "ecdsa-sha2-nistp256"
            unless @key.group.curve_name == "prime256v1"
              raise ArgumentError, "Expected prime256v1 curve, got #{@key.group.curve_name}"
            end
          else
            raise ArgumentError, "Unsupported schema #{schema}"
          end
        end
      end

      class RSA < Key
        def initialize(...)
          super
          raise ArgumentError, "key_type must be rsa, given #{@key_type}" unless @key_type == "rsa"

          unless @key.is_a?(OpenSSL::PKey::RSA)
            raise ArgumentError, "key must be an OpenSSL::PKey::RSA, given #{@key.inspect}"
          end

          case @schema
          when "rsassa-pss-sha256"
            raise Error::UnsupportedPlatform, "RSA-PSS verification unsupported" unless @key.respond_to?(:verify_pss)
          when "rsa-pkcs1v15-sha256"
            # supported
          else
            raise ArgumentError, "Unsupported schema #{schema}"
          end
        end

        def verify(_algo, signature, data)
          case @schema
          when "rsassa-pss-sha256"
            @key.verify_pss("sha256", signature, data, salt_length: :auto, mgf1_hash: "SHA256")
          when "rsa-pkcs1v15-sha256"
            super
          else
            raise ArgumentError, "Unsupported schema #{schema}"
          end
        end
      end

      class ED25519 < Key
        def self.pkey_from_der(raw)
          if OpenSSL::PKey.respond_to?(:new_raw_public_key)
            OpenSSL::PKey.new_raw_public_key("ed25519", raw)
          else
            pem = <<~PEM
              -----BEGIN PUBLIC KEY-----
              MCowBQYDK2VwAyEA#{Internal::Util.base64_encode(raw)}
              -----END PUBLIC KEY-----
            PEM
            OpenSSL::PKey.read(pem)
          end
        end

        def initialize(...)
          super
          unless @key_type == "ed25519"
            raise ArgumentError,
                  "key_type must be ed25519, given #{@key_type}"
          end
          unless @key.is_a?(OpenSSL::PKey::PKey) && @key.oid == "ED25519"
            raise ArgumentError,
                  "key must be an OpenSSL::PKey::PKey with oid ED25519, is #{@key.inspect}"
          end
          raise ArgumentError, "schema must be #{schema}" unless @schema == schema

          case @schema
          when "ed25519"
            # supported
          else
            raise ArgumentError, "Unsupported schema #{schema}"
          end
        end

        def verify(_algo, signature, data)
          super(nil, signature, data)
        end
      end
    end
  end
end
