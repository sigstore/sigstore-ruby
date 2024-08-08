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

require "time"

require_relative "../internal/key"

module Sigstore::TUF
  class Root
    include Sigstore::Loggable

    TYPE = "root"
    attr_reader :version, :consistent_snapshot, :expires

    def initialize(data)
      type = data.fetch("_type")
      raise "Expected type to be #{TYPE}, got #{type.inspect}" unless type == TYPE

      @spec_version = data.fetch("spec_version")
      @consistent_snapshot = data.fetch("consistent_snapshot")
      @version = data.fetch("version")
      @expires = Time.iso8601 data.fetch("expires")
      @keys = data.fetch("keys").to_h do |key_id, key_data|
        key_type = key_data.fetch("keytype")
        scheme = key_data.fetch("scheme")
        keyval = key_data.fetch("keyval")
        public_key_data = keyval.fetch("public")

        key = Sigstore::Internal::Key.read(key_type, scheme, public_key_data, key_id: key_id)

        [key_id, key]
      end
      @roles = data.fetch("roles")
      @unrecognized_fields = data.fetch("unrecognized_fields", {})
    end

    def verify_delegate(type, bytes, signatures)
      role = @roles.fetch(type)
      keyids = role.fetch("keyids")
      threshold = role.fetch("threshold")

      verified_key_ids = Set.new

      signatures.each do |signature|
        key_id = signature.fetch("keyid")
        unless keyids.include?(key_id)
          logger.warn "Unknown key_id=#{key_id.inspect} missing from #{keyids}"
          next
        end

        key = @keys.fetch(key_id)
        signature_bytes = [signature.fetch("sig")].pack("H*")
        verified = key.verify("sha256", signature_bytes, bytes)

        added = verified_key_ids.add?(key_id) if verified
        logger.debug { "key_id=#{key_id.inspect} type=#{type} verified=#{verified} added=#{added.inspect}" }
      end
      count = verified_key_ids.size

      return unless count < threshold

      raise Error::TooFewSignatures,
            "Not enough signatures: found #{count} out of threshold=#{threshold} for #{type}"
    end

    def expired?(reference_time)
      @expires < reference_time
    end
  end
end
