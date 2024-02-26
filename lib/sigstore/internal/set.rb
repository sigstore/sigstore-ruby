# frozen_string_literal: true

module Sigstore
  module Internal
    module SET
      def self.verify_set(client:, entry:)
        raise "invalid log entry: no inclusion promise" unless entry.inclusion_promise

        signed_entry_timestamp = entry.inclusion_promise.unpack1("m0")

        client.rekor_keyring.verify(
          key_id: entry.log_id,
          signature: signed_entry_timestamp,
          data: entry.encode_canonical
        )
      end
    end
  end
end
