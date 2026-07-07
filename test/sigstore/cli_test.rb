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
    # jruby-openssl cannot parse one of the leaf certificate's extensions (raises
    # ExtensionError "unknown tag 13"), so displaying the cert is unsupported there.
    omit_if(RUBY_ENGINE == "jruby", "jruby-openssl cannot parse the certificate's extensions")
    bundle = "#{ASSETS}/happy-path-v0.3/bundle.sigstore.json"
    out, = capture_output do
      assert_nothing_raised { Sigstore::CLI.start(["display", bundle]) }
    end
    assert_match(/Certificate:/, out)
  end

  # --in-toto produces a DSSE bundle, which has no message signature, so the
  # detached --signature/--certificate outputs are rejected up front (before any
  # token detection or network calls).
  data("signature" => "--signature", "certificate" => "--certificate")
  def test_sign_in_toto_rejects_detached_output_flags(flag)
    # exit_on_failure? turns the Thor::InvocationError into a printed message + exit.
    # The flag validation runs before the file is read, so the path need not exist.
    _, err = capture_output do
      assert_raise(SystemExit) do
        Sigstore::CLI.start(["sign", "--in-toto", flag, "out", "statement.json"])
      end
    end
    assert_include err, "--in-toto cannot be combined with --signature or --certificate"
  end
end
