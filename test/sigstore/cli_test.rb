# frozen_string_literal: true

require "test_helper"
require "sigstore/cli"

class Sigstore::CLITest < Test::Unit::TestCase
  ASSETS = "test/sigstore-conformance/test/assets/bundle-verify"

  def test_display_managed_key_bundle
    bundle = "#{ASSETS}/managed-key-happy-path/bundle.sigstore.json"
    out, = capture_output do
      assert_nothing_raised { Sigstore::CLI.start(["display", bundle]) }
    end
    # A managed-key bundle has no certificate; display should report the public key
    # hint rather than crashing on a missing leaf certificate.
    assert_match(%r{Public Key.*TLMsSDfG3ajPsWge\+z/vX5T/zluXnmvbkTkwLIV68Tk=}m, out)
  end

  def test_display_certificate_bundle
    bundle = "#{ASSETS}/happy-path-v0.3/bundle.sigstore.json"
    out, = capture_output do
      assert_nothing_raised { Sigstore::CLI.start(["display", bundle]) }
    end
    assert_match(/Certificate:/, out)
  end
end
