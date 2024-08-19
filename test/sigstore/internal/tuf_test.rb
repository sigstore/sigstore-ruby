# frozen_string_literal: true

require "test_helper"
require "sigstore/tuf"

class Sigstore::TUFTest < Test::Unit::TestCase
  def test_initialize
    updater = Sigstore::TUF::TrustUpdater.new("https://example.com", true)
    assert_equal(
      File.join(
        Dir.home,
        ".cache/sigstore-ruby/segiddins/tuf/https%3A%2F%2Fexample.com/trusted_root.json"
      ),
      updater.trusted_root_path
    )
    refute File.file?(updater.trusted_root_path)
  end

  def test_production_default_dirs
    updater = Sigstore::TUF::TrustUpdater.new("https://tuf-repo-cdn.sigstore.dev", true)
    assert_equal(
      File.join(
        Dir.home,
        ".cache/sigstore-ruby/segiddins/tuf/https%3A%2F%2Ftuf-repo-cdn.sigstore.dev/trusted_root.json"
      ),
      updater.trusted_root_path
    )

    assert File.file?(updater.trusted_root_path)

    assert_equal File.read(updater.trusted_root_path),
                 File.read(File.expand_path("../../../data/_store/prod/trusted_root.json", __dir__))
  end

  def test_staging_default_dirs
    updater = Sigstore::TUF::TrustUpdater.new("https://tuf-repo-cdn.sigstage.dev", true)
    assert_equal(
      File.join(
        Dir.home,
        ".cache/sigstore-ruby/segiddins/tuf/https%3A%2F%2Ftuf-repo-cdn.sigstage.dev/trusted_root.json"
      ),
      updater.trusted_root_path
    )

    assert File.file?(updater.trusted_root_path)

    assert_equal File.read(updater.trusted_root_path),
                 File.read(File.expand_path("../../../data/_store/staging/trusted_root.json", __dir__))
  end

  def test_initialize_custom_dirs
    targets_dir = File.join(Dir.home, "custom-targets")
    metadata_dir = File.join(Dir.home, "custom-metadata")
    updater = Sigstore::TUF::TrustUpdater.new("https://tuf-repo-cdn.sigstore.dev", true,
                                              metadata_dir: metadata_dir, targets_dir: targets_dir)
    assert_equal(File.join(targets_dir, "trusted_root.json"), updater.trusted_root_path)
  end
end
