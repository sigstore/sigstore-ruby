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

      def as_transparency_log_entry
        entry = Rekor::V1::TransparencyLogEntry.new
        entry.log_index = log_index
        entry.log_id = Common::V1::LogId.new.tap { |id| id.key_id = [log_id].pack("H*") }
        entry.kind_version = Rekor::V1::KindVersion.new.tap do |kind_version|
          kind_version.kind = "hashedrekord"
          kind_version.version = "0.0.1"
        end
        entry.integrated_time = integrated_time
        entry.inclusion_promise = Rekor::V1::InclusionPromise.new.tap do |promise|
          promise.signed_entry_timestamp = inclusion_promise.unpack1("m0")
        end
        entry.inclusion_proof = inclusion_proof.as_proto
        entry.canonicalized_body = body.unpack1("m0")
        entry
      end

      def self.from_proto(tlog_entry)
        if tlog_entry.inclusion_proof&.checkpoint&.envelope
          parsed_inclusion_proof = InclusionProof.from_proto(tlog_entry.inclusion_proof)
        end

        new(
          uuid: nil,
          body: [tlog_entry.canonicalized_body].pack("m0"),
          integrated_time: tlog_entry.integrated_time,
          log_id: tlog_entry.log_id.key_id.unpack1("H*"),
          log_index: tlog_entry.log_index,
          inclusion_proof: parsed_inclusion_proof,
          inclusion_promise: [tlog_entry.inclusion_promise.signed_entry_timestamp].pack("m0")
        )
      end
    end

    InclusionProof = Struct.new(:checkpoint, :hashes, :log_index, :root_hash, :tree_size, keyword_init: true) do
      def self.from_proto(inclusion_proof)
        new(
          checkpoint: inclusion_proof.checkpoint.envelope,
          hashes: inclusion_proof.hashes.map { |h| h.unpack1("H*") },
          log_index: inclusion_proof.log_index,
          root_hash: inclusion_proof.root_hash.unpack1("H*"),
          tree_size: inclusion_proof.tree_size
        )
      end

      def as_proto
        inclusion_proof = Rekor::V1::InclusionProof.new
        inclusion_proof.checkpoint = Rekor::V1::Checkpoint.new
        inclusion_proof.checkpoint.envelope = checkpoint
        inclusion_proof.hashes = hashes.map { |h| [h].pack("H*") }
        inclusion_proof.log_index = log_index
        inclusion_proof.root_hash = [root_hash].pack("H*")
        inclusion_proof.tree_size = tree_size
        inclusion_proof
      end
    end
  end
end
