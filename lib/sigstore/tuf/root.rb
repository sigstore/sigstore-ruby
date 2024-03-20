# frozen_string_literal: true

require "time"

module Sigstore::TUF
  class Root
    TYPE = "root"
    attr_reader :version, :consistent_snapshot, :expires

    def initialize(data)
      type = data.fetch("_type")
      raise "Expected type to be #{TYPE}, got #{type.inspect}" unless type == TYPE

      @spec_version = data.fetch("spec_version")
      @consistent_snapshot = data.fetch("consistent_snapshot")
      @version = data.fetch("version")
      @expires = Time.iso8601 data.fetch("expires")
      @keys = data.fetch("keys").transform_values do |key_data|
        key_type = key_data.fetch("keytype")
        scheme = key_data.fetch("scheme")
        keyval = key_data.fetch("keyval")
        public_key_data = keyval.fetch("public")

        # TODO: https://github.com/secure-systems-lab/securesystemslib/blob/main/securesystemslib/signer/__init__.py#L47
        case [key_type, scheme]
        when %w[ecdsa-sha2-nistp256 ecdsa-sha2-nistp256],
             %w[ecdsa ecdsa-sha2-nistp256]
          key = OpenSSL::PKey.read(public_key_data)
          unless key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == "prime256v1"
            raise "Expected #{scheme} key, got #{key.class} #{key.group.curve_name}"
          end
        # when %w[ed25519 ed25519]
        else
          raise "Unsupported scheme & key type: #{scheme}, #{key_type}"
        end

        if RUBY_ENGINE == "jruby" && key.to_pem != key_data && key.to_der != key_data
          raise "Key mismatch: #{key.to_pem.inspect} != #{key_data.inspect}"
        end

        key
      end
      @roles = data.fetch("roles")
      @unrecognized_fields = data.fetch("unrecognized_fields", {})
    end

    def verify_delegate(type, bytes, signatures)
      role = @roles.fetch(type)
      keyids = role.fetch("keyids")
      threshold = role.fetch("threshold")

      verified_key_ids = Set.new

      count = signatures.count do |signature|
        next unless keyids.include?(signature.fetch("keyid"))

        key = @keys.fetch(signature.fetch("keyid"))
        signature_bytes = [signature.fetch("sig")].pack("H*")
        verified = key.verify("sha256", signature_bytes, bytes)

        verified_key_ids.add?(signature.fetch("keyid")) if verified
      end

      raise "Not enough signatures: found #{count} out of threshold=#{threshold}" if count < threshold
    end

    def expired?(reference_time)
      @expires < reference_time
    end
  end
end
