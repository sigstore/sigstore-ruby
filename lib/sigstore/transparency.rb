# frozen_string_literal: true

module Sigstore
  module Transparency
    LogEntry = Struct.new(:uuid, :body, :integrated_time, :log_id, :log_index, :inclusion_proof, :inclusion_promise,
                          keyword_init: true) do
      # @implements LogEntry

      def initialize(**)
        super

        return unless !inclusion_proof&.checkpoint && !inclusion_promise

        raise ArgumentError,
              "LogEntry must have either inclusion_proof or inclusion_promise"
      end

      def self.from_response(response)
        raise ArgumentError, "response must be a Hash" unless response.is_a?(Hash)
        raise ArgumentError, "Received multiple entries in response" if response.size != 1

        uuid, entry = response.first

        body = JSON.parse entry["body"].unpack1("m0")
        unless body.is_a?(Hash) && body["kind"] == "hashedrekord" && body["apiVersion"] == "0.0.1"
          raise "Invalid entry body: #{body.inspect}. Expected kind: hashedrekord, apiVersion: 0.0.1"
        end

        new(
          uuid: uuid,
          body: entry["body"],
          integrated_time: entry["integratedTime"],
          log_id: entry["logID"],
          log_index: entry["logIndex"],
          inclusion_proof: entry.dig("verification", "inclusionProof")&.then do |proof|
                             InclusionProof.new(
                               checkpoint: proof["checkpoint"],
                               hashes: proof["hashes"],
                               log_index: proof["logIndex"],
                               root_hash: proof["rootHash"],
                               tree_size: proof["treeSize"]
                             )
                           end,
          inclusion_promise: entry.dig("verification", "signedEntryTimestamp")
        )
      end

      # https://www.rfc-editor.org/rfc/rfc8785
      def encode_canonical
        JSON.dump(
          body: body,
          integratedTime: integrated_time,
          logID: log_id,
          logIndex: log_index
        )
      end
    end

    InclusionProof = Struct.new(:checkpoint, :hashes, :log_index, :root_hash, :tree_size, keyword_init: true)
  end
end
