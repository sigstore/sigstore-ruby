# frozen_string_literal: true

require "test_helper"
require "sigstore/transparency"

class Sigstore::Transparency::LogEntryTest < Test::Unit::TestCase
  def test_consistency
    e = assert_raise(ArgumentError) do
      Sigstore::Transparency::LogEntry.new(
        uuid: "fake",
        body: ["fake"].pack("m0"),
        integrated_time: 0,
        log_id: "1234",
        log_index: 1,
        inclusion_proof: nil,
        inclusion_promise: nil
      )
    end

    assert_equal("LogEntry must have either inclusion_proof or inclusion_promise", e.message)
  end

  def test_from_response
    body = {
      "kind" => "hashedrekord",
      "apiVersion" => "0.0.1"
    }
    entry = Sigstore::Transparency::LogEntry.from_response(
      "fake" => {
        "body" => [JSON.dump(body)].pack("m0"),
        "integratedTime" => 0,
        "logID" => "1234",
        "logIndex" => 1,
        "verification" => {
          "inclusionProof" => {
            "checkpoint" => "fake",
            "hashes" => ["fake"],
            "logIndex" => 1,
            "rootHash" => "fake",
            "treeSize" => 1
          }
        }
      }
    )

    assert_equal Sigstore::Transparency::LogEntry.new(
      uuid: "fake",
      body: [JSON.dump(body)].pack("m0"),
      integrated_time: 0,
      log_id: "1234",
      log_index: 1,
      inclusion_proof: Sigstore::Transparency::InclusionProof.new(
        checkpoint: "fake",
        hashes: ["fake"],
        log_index: 1,
        root_hash: "fake",
        tree_size: 1
      ),
      inclusion_promise: nil
    ), entry

    e = assert_raise(ArgumentError) do
      Sigstore::Transparency::LogEntry.from_response([])
    end
    assert_equal("response must be a Hash", e.message)

    e = assert_raise(ArgumentError) do
      Sigstore::Transparency::LogEntry.from_response("fake" => {}, "fake2" => {})
    end
    assert_equal("Received multiple entries in response", e.message)

    e = assert_raise(RuntimeError) do
      Sigstore::Transparency::LogEntry.from_response(
        "fake" => {
          "body" => [JSON.dump({})].pack("m0"),
          "integratedTime" => 0,
          "logID" => "1234",
          "logIndex" => 1,
          "verification" => {
            "inclusionProof" => {
              "checkpoint" => "fake",
              "hashes" => ["fake"],
              "logIndex" => 1,
              "rootHash" => "fake",
              "treeSize" => 1
            }
          }
        }
      )
    end
    assert_equal("Invalid entry body: {}. Expected kind: hashedrekord, apiVersion: 0.0.1", e.message)
  end

  def test_encode_canonical
    body = {
      "kind" => "hashedrekord",
      "apiVersion" => "0.0.1"
    }
    entry = Sigstore::Transparency::LogEntry.from_response(
      "fake" => {
        "body" => [JSON.dump(body)].pack("m0"),
        "integratedTime" => 0,
        "logID" => "1234",
        "logIndex" => 1,
        "verification" => {
          "inclusionProof" => {
            "checkpoint" => "fake",
            "hashes" => ["fake"],
            "logIndex" => 1,
            "rootHash" => "fake",
            "treeSize" => 1
          }
        }
      }
    )

    assert_equal <<~CANONICAL.chomp, entry.encode_canonical
      {"body":"eyJraW5kIjoiaGFzaGVkcmVrb3JkIiwiYXBpVmVyc2lvbiI6IjAuMC4xIn0=","integratedTime":0,"logID":"1234","logIndex":1}
    CANONICAL
  end
end
