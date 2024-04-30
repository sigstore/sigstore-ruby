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
    class Keyring
      def initialize(keys:)
        @keyring = {}
        keys.each do |key_bytes|
          key = OpenSSL::PKey.read(key_bytes)
          @keyring[OpenSSL::Digest::SHA256.hexdigest(key.public_to_der)] = key
        end
      end

      def verify(key_id:, signature:, data:)
        key = @keyring.fetch(key_id) { raise KeyError, "key not found: #{key_id.inspect}, known: #{@keyring.keys}" }

        return true \
          if case key
             when OpenSSL::PKey::EC
               key.verify("SHA256", signature, data)
             when OpenSSL::PKey::RSA
               key.verify("SHA256", signature, data, { rsa_padding_mode: "pkcs1" })
             else
               raise "unsupported key type #{key}"
             end

        raise("invalid signature: #{signature.inspect} over #{data.inspect} with key #{key_id.inspect}")
      end
    end
  end
end
