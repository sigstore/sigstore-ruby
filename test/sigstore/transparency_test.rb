# frozen_string_literal: true

require "test_helper"

require "sigstore/internal/merkle"

class Sigstore::InclusionProofTest < Test::Unit::TestCase
  def test_hasher
    [
      # ["RFC6962 Empty", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ],
      ["RFC6962 Empty Leaf", "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
       Sigstore::Internal::Merkle.hash_leaf("")],
      ["RFC6962 Single Leaf", "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56",
       Sigstore::Internal::Merkle.hash_leaf("L123456")],
      ["RFC6962 Node", "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb",
       Sigstore::Internal::Merkle.hash_children("N123", "N456")]
    ].each do |desc, got, want|
      got_hex = [got].pack("H*")
      assert_equal got_hex, want, desc
    end
  end

  def test_hasher_collisions
    leaf1 = "Hello"
    leaf2 = "World"

    hash1 = Sigstore::Internal::Merkle.hash_leaf(leaf1)
    hash2 = Sigstore::Internal::Merkle.hash_leaf(leaf2)

    refute_equal hash1, hash2, "Leaf hashes should differ"

    sub_hash1 = Sigstore::Internal::Merkle.hash_children(hash1, hash2)
    preimage = "#{hash1}#{hash2}"
    forged_hash = Sigstore::Internal::Merkle.hash_leaf(preimage)

    refute_equal sub_hash1, forged_hash, "Hasher is not second-preimage resistant"

    sub_hash2 = Sigstore::Internal::Merkle.hash_children(hash2, hash1)

    refute_equal sub_hash1, sub_hash2, "Hasher is not order-sensitive"
  end

  def test_verify_inclusion_single_entry
    data = "data"
    # Root and leaf hash for 1-entry tree are the same.
    hash = Sigstore::Internal::Merkle.hash_leaf(data)
    # The corresponding inclusion proof is empty.
    proof = []
    empty_hash = ""

    [
      [hash, hash, false],
      [hash, empty_hash, true],
      [empty_hash, hash, true],
      [empty_hash, empty_hash, true] # wrong hash size
    ].each do |root, leaf, want_err|
      blk = proc do
        Sigstore::Internal::Merkle.verify_inclusion(
          0, 1, proof, root, leaf
        )
      end
      if want_err
        assert_raise(Sigstore::Internal::Merkle::InvalidInclusionProofError, &blk)
      else
        blk.call
      end
    end
  end

  # dumped from https://github.com/transparency-dev/merkle/blob/main/proof/verify_test.go
  File.open(File.expand_path("data/transparency/merkle/verify_inclusion.jsonl", __dir__)) do |f|
    f.each_line.map do |l|
      c = JSON.parse(l)

      test c["desc"] do
        blk = proc {
          proof = (c["proof"] || []).map { |h| Sigstore::Internal::Util.base64_decode h }
          root = Sigstore::Internal::Util.base64_decode c["root"]
          leaf_hash = Sigstore::Internal::Util.base64_decode c["leaf_hash"]
          verifier_check(
            c["desc"], c["index"], c["size"], proof, root, leaf_hash
          )
        }

        if c["expected_error"]
          assert_raise(Sigstore::Internal::Merkle::InvalidInclusionProofError,
                       Sigstore::Internal::Merkle::InclusionProofSizeError,
                       c.inspect, &blk)
        else
          assert_nothing_raised(c.inspect, &blk)
        end
      end
    end
  end

  def verifier_check(desc, log_index, tree_size, proof, root, leaf_hash)
    got = Sigstore::Internal::Merkle.root_from_inclusion_proof(
      log_index, tree_size, proof, leaf_hash
    )

    Sigstore::Internal::Merkle.verify_inclusion(
      log_index, tree_size, proof, root, leaf_hash
    )

    assert_equal Sigstore::Internal::Util.base64_encode(root), Sigstore::Internal::Util.base64_encode(got),
                 "#{desc}: got root #{got.inspect}, want #{root.inspect}"
    assert_equal root, got, "#{desc}: got root #{got.inspect}, want #{root.inspect}"
  end
end
