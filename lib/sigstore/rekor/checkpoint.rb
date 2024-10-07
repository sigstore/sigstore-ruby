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
  module Rekor
    module Checkpoint
      Signature = Struct.new(:name, :sig_hash, :signature, keyword_init: true)

      SignedCheckpoint = Struct.new(:signed_note, :checkpoint, keyword_init: true) do
        # @implements SignedCheckpoint

        def self.from_text(text)
          signed_note = SignedNote.from_text(text)
          checkpoint = LogCheckpoint.from_text(signed_note.note)

          new(signed_note:, checkpoint:)
        end
      end

      SignedNote = Struct.new(:note, :signatures, keyword_init: true) do
        # @implements SignedNote

        def self.from_text(text)
          separator = "\n\n"

          raise Error::InvalidCheckpoint, "Note must include double newline separator" unless text.include?(separator)

          note, signatures = text.split(separator, 2)
          raise Error::InvalidCheckpoint, "must contain at least one signature" if signatures.empty?
          raise Error::InvalidCheckpoint, "signatures must end with a newline" unless signatures.end_with?("\n")

          note << "\n"

          sig_parser = %r{^\u2014 (?<name>[^[[:space:]]+]+) (?<signature>[0-9A-Za-z+/=-]+)\n}

          signatures = signatures.lines.map! do |line|
            raise Error::InvalidCertificate, "Invalid signature line: #{line.inspect}" unless sig_parser =~ line

            name = Regexp.last_match[:name]
            signature = Regexp.last_match[:signature]

            signature_bytes = signature.unpack1("m0")
            raise Error::InvalidCheckpoint, "too few bytes in signature" if signature_bytes.bytesize < 5

            sig_hash = signature_bytes.slice!(0, 4).unpack1("a4")

            Signature.new(name:, sig_hash:, signature: signature_bytes)
          end

          new(note:, signatures:)
        end

        def verify(rekor_keyring, key_id)
          data = note.encode("utf-8")
          signatures.each do |signature|
            sig_hash = key_id[0, 4]
            if signature.sig_hash != sig_hash
              raise Error::InvalidCheckpoint,
                    "sig_hash hint #{signature.sig_hash.inspect} does not match key_id #{sig_hash.inspect}"
            end

            rekor_keyring.verify(key_id: key_id.unpack1("H*"), signature: signature.signature, data:)
          end
        end
      end

      LogCheckpoint = Struct.new(:origin, :log_size, :log_hash, :other_content, keyword_init: true) do
        # @implements LogCheckpoint

        def self.from_text(text)
          lines = text.strip.split("\n")

          raise Error::InvalidCheckpoint, "too few items in header" if lines.size < 3

          origin = lines.shift
          log_size = lines.shift.to_i
          root_hash = lines.shift.unpack1("m0")

          raise Error::InvalidCheckpoint, "empty origin" if origin.empty?

          new(origin:, log_size:, log_hash: root_hash, other_content: lines)
        end
      end

      def self.verify_checkpoint(rekor_keyring, entry)
        raise Error::InvalidRekorEntry, "Rekor entry has no inclusion proof" unless entry.inclusion_proof

        signed_checkpoint = SignedCheckpoint.from_text(entry.inclusion_proof.checkpoint.envelope)
        signed_checkpoint.signed_note.verify(rekor_keyring, entry.log_id.key_id)

        checkpoint_hash = signed_checkpoint.checkpoint.log_hash
        root_hash = entry.inclusion_proof.root_hash

        return if checkpoint_hash == root_hash

        raise Error::InvalidRekorEntry, "Inclusion proof contains invalid root hash: " \
                                        "expected #{checkpoint_hash.inspect}, calculated #{root_hash.inspect}"
      end
    end
  end
end
