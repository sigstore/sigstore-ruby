# frozen_string_literal: true

require "test_helper"
require "sigstore/tuf/trusted_metadata_set"

class Sigstore::TUF::TrustedMetadataSetTest < Test::Unit::TestCase
  setup do
    @reference_time = Time.utc(12, 42, 2, 7, 3, 2023, 4, 67, false, "UTC")
    @priv_key = OpenSSL::PKey::RSA.new(2048)
    @root = {
      "signed" => {
        "_type" => "root",
        "spec_version" => "1.0.0",
        "consistent_snapshot" => false,
        "version" => 1,
        "expires" => "2023-07-03T12:42:02Z",
        "keys" => {},
        "roles" => {
          "root" => {
            "keyids" => [],
            "threshold" => 0
          },
          "timestamp" => {
            "keyids" => [],
            "threshold" => 0
          },
          "snapshot" => {
            "keyids" => [],
            "threshold" => 0
          }
        }
      },
      "signatures" => []
    }
    @timestamp = {
      "signed" => {
        "_type" => "timestamp",
        "version" => 1,
        "spec_version" => "1.0.0",
        "expires" => "2023-07-03T12:42:02Z",
        "meta" => {
          "snapshot.json" => {
            "version" => 137,
            "length" => 104,
            "hashes" => {}
          }
        }
      },
      "signatures" => []
    }
    @snapshot = {
      "signed" => {
        "_type" => "snapshot",
        "version" => 137,
        "expires" => "2023-07-03T12:42:02Z",
        "meta" => {}
      },
      "signatures" => []
    }
    # TODO: need to generate a test root, with keys we can use for signing
    @root_data = JSON.dump(@root)
    @set = Sigstore::TUF::TrustedMetadataSet.new(@root_data, "json", reference_time: @reference_time)
  end

  def test_initialize_known_good
    @root_data = File.read(File.expand_path("../../../data/_store/prod/root.json", __dir__))
    Sigstore::TUF::TrustedMetadataSet.new(@root_data, "json", reference_time: @reference_time)
  end

  def test_initialize
    assert @set.root

    # allows loading expired metadata from the (already truted) root
    @reference_time += 60 * 60 * 24 * 365 * 20
    Sigstore::TUF::TrustedMetadataSet.new(@root_data, "json", reference_time: @reference_time)
  end

  def test_raises_when_updating_root_after_timestamp
    @set.timestamp = JSON.dump(@timestamp)
    e = assert_raise(Sigstore::TUF::Error::BadUpdateOrder) do
      @set.root = @root_data
    end

    assert_equal "cannot update root after timestamp", e.message
  end

  def test_raises_when_updating_snapshot_before_timestamp
    e = assert_raise(Sigstore::TUF::Error::BadUpdateOrder) do
      @set.snapshot = JSON.dump(@snapshot)
    end

    assert_equal "cannot update snapshot before timestamp", e.message
  end

  def test_raises_when_updating_timestamp_after_snapshot
    @set.timestamp = JSON.dump(@timestamp)
    @set.snapshot = JSON.dump(@snapshot)
    e = assert_raise(Sigstore::TUF::Error::BadUpdateOrder) do
      @set.timestamp = JSON.dump(@timestamp)
    end

    assert_equal "cannot update timestamp after snapshot", e.message
  end
end
