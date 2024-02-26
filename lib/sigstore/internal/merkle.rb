# frozen_string_literal: true

require_relative "util"

module Sigstore
  module Internal
    module Merkle
      def self.verify_merkle_inclusion(entry)
        inclusion_proof = entry.inclusion_proof
        raise "Rekor entry has no inclusion proof" unless inclusion_proof

        inner, border = decompose_inclusion_proof(inclusion_proof.log_index, inclusion_proof.tree_size)

        if inclusion_proof.hashes.size != inner + border
          raise "Inclusion proof has wrong size, expected #{inner + border} hashes, got #{inclusion_proof.hashes.size}"
        end

        leaf_hash = hash_leaf(Util.base64_decode(entry.body))

        intermediate_result = chain_inner(leaf_hash, (inclusion_proof.hashes[...inner] || raise),
                                          inclusion_proof.log_index)

        calc_hash = chain_border_right(intermediate_result,
                                       inclusion_proof.hashes[inner..] || raise).unpack1("H*").encode("utf-8")

        return if calc_hash == inclusion_proof.root_hash

        raise "Inclusion proof contains invalid root hash: expected #{inclusion_proof}, calculated #{calc_hash}"
      end

      def self.decompose_inclusion_proof(log_index, tree_size)
        inner = (log_index ^ (tree_size - 1)).bit_length
        border = (log_index >> inner).to_s(2).count("1")

        [inner, border]
      end

      def self.hash_leaf(data)
        data = "\u0000#{data}".b
        OpenSSL::Digest.new("SHA256").digest(data) # : String & Util::binaryString
      end

      def self.chain_inner(seed, hashes, log_index)
        hashes.each_with_index do |hash, i|
          hash = Util.hex_decode(hash)
          seed = if ((log_index >> i) & 1).zero?
                   hash_children(seed, hash)
                 else
                   hash_children(hash, seed)
                 end
        end
        seed
      end

      def self.chain_border_right(seed, hashes)
        hashes.reduce(seed) do |acc, hash|
          hash = Util.hex_decode(hash)
          hash_children(hash, acc)
        end
      end

      def self.hash_children(left, right)
        data = "\u0001#{left}#{right}".b
        OpenSSL::Digest.new("SHA256").digest(data) # : String & Util::binaryString
      end
    end
  end
end
