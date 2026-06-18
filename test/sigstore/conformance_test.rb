# frozen_string_literal: true

require "test_helper"
require "sigstore/cli"

class Sigstore::ConformanceTest < Test::Unit::TestCase
  # sigstore-conformance reorganized its fixtures under test/assets/bundle-verify/<case>/.
  # Each case provides a bundle.sigstore.json (and optionally its own artifact and
  # trusted_root.json); when no artifact is present the shared parent a.txt is used.
  ASSETS = "test/sigstore-conformance/test/assets/bundle-verify"
  IDENTITY = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon" \
             "/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
  ISSUER = "https://token.actions.githubusercontent.com"
  # These bundles embed historical (already-expired) signing certificates, so verification
  # is anchored to the entry's integrated time rather than the wall clock. Verifying offline
  # against the vendored production trusted root keeps the tests deterministic and network-free.
  PROD_TRUSTED_ROOT = "data/_store/prod/trusted_root.json"

  def verify(case_name, trusted_root: PROD_TRUSTED_ROOT, artifact: "#{ASSETS}/a.txt")
    Sigstore::CLI.start([
                          "verify",
                          "--offline",
                          "--trusted-root", trusted_root,
                          "--certificate-identity", IDENTITY,
                          "--certificate-oidc-issuer", ISSUER,
                          "--bundle", "#{ASSETS}/#{case_name}/bundle.sigstore.json",
                          artifact
                        ])
  end

  def test_verify_signature_invalid
    capture_output do
      e = assert_raise SystemExit do
        verify("signature-mismatch_fail")
      end
      assert_equal 1, e.status
    end
  end

  def test_verify_bundle_success
    capture_output do
      assert_nothing_raised do
        verify("happy-path-v0.3")
      end
    end
  end

  def test_verify_dsse_bundle_with_trust_root
    case_name = "intoto-with-custom-trust-root"
    capture_output do
      assert_nothing_raised do
        verify(case_name,
               trusted_root: "#{ASSETS}/#{case_name}/trusted_root.json",
               artifact: "#{ASSETS}/#{case_name}/artifact")
      end
    end
  end

  # Drive the Rekor v2 (hashedrekord 0.0.2) path end-to-end, offline, against the
  # per-case staging-derived trusted root that carries the v2 Ed25519 log key and the
  # timestamp authority. v2 entries have no integrated time, so these bundles rely on
  # the embedded TSA timestamp for the signing time. Each case ships its own
  # trusted_root.json (see the case READMEs).
  def verify_rekor2(case_name)
    verify(case_name, trusted_root: "#{ASSETS}/#{case_name}/trusted_root.json")
  end

  def test_verify_rekor2_message_signature_happy_path
    capture_output do
      assert_nothing_raised { verify_rekor2("rekor2-happy-path") }
    end
  end

  def test_verify_rekor2_dsse_happy_path
    capture_output do
      assert_nothing_raised { verify_rekor2("rekor2-dsse-happy-path") }
    end
  end

  def test_verify_rekor2_missing_inclusion_proof_fails
    capture_output do
      e = assert_raise(SystemExit) { verify_rekor2("rekor2-no-inclusion-proof_fail") }
      assert_equal 1, e.status
    end
  end

  def test_verify_rekor2_missing_timestamp_fails
    capture_output do
      e = assert_raise(SystemExit) { verify_rekor2("rekor2-no-timestamp_fail") }
      assert_equal 1, e.status
    end
  end

  # Managed-key ("bring your own key") verification: the bundle carries a public key
  # hint instead of a Fulcio certificate, and the verifying key is supplied out-of-band
  # via --key. There is no identity to check, so certificate-path/SCT/identity steps are
  # skipped; the signature and the Rekor entry are still bound to the supplied key.
  def verify_key(case_name, trusted_root: PROD_TRUSTED_ROOT, key: "#{ASSETS}/#{case_name}/key.pub")
    args = ["verify", "--offline", "--trusted-root", trusted_root,
            "--bundle", "#{ASSETS}/#{case_name}/bundle.sigstore.json", "#{ASSETS}/a.txt"]
    args.push("--key", key) if key
    Sigstore::CLI.start(args)
  end

  def test_verify_managed_key_happy_path
    capture_output do
      assert_nothing_raised { verify_key("managed-key-happy-path") }
    end
  end

  def test_verify_managed_key_with_trusted_root
    case_name = "managed-key-and-trusted-root"
    capture_output do
      assert_nothing_raised do
        verify_key(case_name, trusted_root: "#{ASSETS}/#{case_name}/trusted_root.json")
      end
    end
  end

  def test_verify_managed_key_no_key_fails
    capture_output do
      e = assert_raise(SystemExit) { verify_key("managed-key-no-key_fail", key: nil) }
      assert_equal 1, e.status
    end
  end

  def test_verify_managed_key_wrong_key_fails
    capture_output do
      e = assert_raise(SystemExit) { verify_key("managed-key-wrong-key_fail") }
      assert_equal 1, e.status
    end
  end
end
