# frozen_string_literal: true

require "test_helper"
require "rubygems/commands/sigstore_verify_command"
require "rubygems/commands/sigstore_verify_bundle_command"

class Sigstore::ConformanceTest < Test::Unit::TestCase
  def test_verify_signature_invalid
    VCR.use_cassette("conformance/verify_signature_invalid") do |cassette|
      Timecop.freeze(cassette.originally_recorded_at || Time.now) do
        capture_output do
          assert_raise Gem::SystemExitException do
            Gem::Commands::SigstoreVerifyCommand.new.invoke(
              "--signature", "test/sigstore-conformance/test/assets/a.txt.invalid.sig",
              "--certificate", "test/sigstore-conformance/test/assets/a.txt.invalid.crt",
              "--certificate-identity", "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
              "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
              "test/sigstore-conformance/test/assets/a.txt"
            )
          end
        end
      end
    end
  end

  def test_verify_success
    VCR.use_cassette("conformance/verify_signature_success") do
      capture_output do
        assert_nothing_raised do
          Gem::Commands::SigstoreVerifyCommand.new.invoke(
            "--signature", "test/sigstore-conformance/test/assets/a.txt.good.sig",
            "--certificate", "test/sigstore-conformance/test/assets/a.txt.good.crt",
            "--certificate-identity", "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--trusted-root", "test/sigstore-conformance/test/assets/trusted_root.public_good.json",
            "test/sigstore-conformance/test/assets/a.txt"
          )
        end
      end
    end
  end

  def test_verify_bundle_success
    VCR.use_cassette("conformance/verify_bundle_success") do |cassette|
      Timecop.freeze(cassette.originally_recorded_at || Time.now) do
        capture_output do
          assert_nothing_raised do
            Gem::Commands::SigstoreVerifyBundleCommand.new.invoke(
              "--bundle", "test/sigstore-conformance/test/assets/a.txt.good.sigstore.json",
              "--certificate-identity", "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
              "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
              "test/sigstore-conformance/test/assets/a.txt"
            )
          end
        end
      end
    end
  end

  def test_verify_dsse_bundle_with_trust_root
    capture_output do
      assert_nothing_raised do
        Gem::Commands::SigstoreVerifyBundleCommand.new.invoke(
          "--bundle", "test/sigstore-conformance/test/assets/d.txt.good.sigstore.json",
          "--certificate-identity", "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
          "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
          "--trusted-root", "test/sigstore-conformance/test/assets/trusted_root.d.json",
          "--offline",
          "test/sigstore-conformance/test/assets/d.txt"
        )
      end
    end
  end
end
