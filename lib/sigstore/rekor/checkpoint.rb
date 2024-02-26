# frozen_string_literal: true

module Sigstore
  module Rekor
    module Checkpoint
      Signature = Struct.new(:name, :sig_hash, :signature, keyword_init: true)

      SignedCheckpoint = Struct.new(:signed_note, :checkpoint, keyword_init: true) do
        # @implements SignedCheckpoint

        def self.from_text(text)
          signed_note = SignedNote.from_text(text)
          checkpoint = LogCheckpoint.from_text(signed_note.note)

          new(signed_note: signed_note, checkpoint: checkpoint)
        end
      end

      SignedNote = Struct.new(:note, :signatures, keyword_init: true) do
        # @implements SignedNote

        def self.from_text(text)
          separator = "\n\n"

          raise "Note must ..." unless text.include?(separator)

          note, signatures = text.split(separator, 2)
          raise "must contain at least one signature" if signatures.empty?
          raise "signatures must end with a newline" unless signatures.end_with?("\n")

          note << "\n"

          sig_parser = %r{^\u2014 (?<name>[^[[:space:]]+]+) (?<signature>[0-9A-Za-z+/=-]+)\n}

          signatures = signatures.lines.map! do |line|
            raise "Invalid signature line: #{line.inspect}" unless sig_parser =~ line

            name = Regexp.last_match[:name]
            signature = Regexp.last_match[:signature]

            signature_bytes = signature.unpack1("m0")
            raise "too few bytes in signature" if signature_bytes.bytesize < 5

            sig_hash = signature_bytes.slice!(0, 4).unpack1("a4")

            Signature.new(name: name, sig_hash: sig_hash, signature: signature_bytes)
          end

          new(note: note, signatures: signatures)
        end

        def verify(client, key_id)
          data = note.encode("utf-8")
          signatures.each do |signature|
            sig_hash = key_id[0, 4]
            if signature.sig_hash != sig_hash
              raise "sig_hash hint #{signature.sig_hash.inspect} does not match key_id #{sig_hash.inspect}"
            end

            client.rekor_keyring.verify(key_id: key_id.unpack1("H*"), signature: signature.signature, data: data)
          end
        end
      end

      LogCheckpoint = Struct.new(:origin, :log_size, :log_hash, :other_content, keyword_init: true) do
        # @implements LogCheckpoint

        def self.from_text(text)
          lines = text.strip.split("\n")

          raise "too few items in header" if lines.size < 3

          origin = lines.shift
          log_size = lines.shift.to_i
          root_hash = lines.shift.unpack1("m0").unpack1("H*")

          raise "empty origin" if origin.empty?

          new(origin: origin, log_size: log_size, log_hash: root_hash, other_content: lines)
        end
      end

      def self.verify_checkpoint(client, entry)
        raise "Rekor entry has no inclusion proof" unless entry.inclusion_proof

        signed_checkpoint = SignedCheckpoint.from_text(entry.inclusion_proof.checkpoint)
        signed_checkpoint.signed_note.verify(client, [entry.log_id].pack("H*"))

        checkpoint_hash = signed_checkpoint.checkpoint.log_hash
        root_hash = entry.inclusion_proof.root_hash

        return if checkpoint_hash == root_hash

        raise "Inclusion proof contains invalid root hash: expected #{checkpoint_hash.inspect}, calculated #{root_hash.inspect}"
      end
    end
  end
end
