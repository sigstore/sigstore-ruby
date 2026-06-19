# frozen_string_literal: true

require "test_helper"
require "sigstore/signing_config"

class Sigstore::SigningConfigTest < Test::Unit::TestCase
  # A v0.2 signing config modeled on the staging config: several Rekor tlog
  # services (a current v2, two retired v2s, and a v1) plus single Fulcio/OIDC/TSA
  # entries. Service selection should pick the currently-valid, highest-version
  # service per operator.
  STAGING_LIKE = {
    "mediaType" => "application/vnd.dev.sigstore.signingconfig.v0.2+json",
    "caUrls" => [
      { "url" => "https://fulcio.example", "majorApiVersion" => 1,
        "validFor" => { "start" => "2022-04-14T21:38:40Z" }, "operator" => "example.dev" }
    ],
    "oidcUrls" => [
      { "url" => "https://oauth2.example/auth", "majorApiVersion" => 1,
        "validFor" => { "start" => "2025-04-16T00:00:00Z" }, "operator" => "example.dev" }
    ],
    "rekorTlogUrls" => [
      { "url" => "https://log-alpha3.example", "majorApiVersion" => 2,
        "validFor" => { "start" => "2025-09-22T11:00:00Z" }, "operator" => "example.dev" },
      { "url" => "https://log-alpha1.example", "majorApiVersion" => 2,
        "validFor" => { "start" => "2025-05-07T12:00:00Z", "end" => "2025-08-20T07:24:08Z" },
        "operator" => "example.dev" },
      { "url" => "https://rekor-v1.example", "majorApiVersion" => 1,
        "validFor" => { "start" => "2021-01-12T11:53:27Z" }, "operator" => "example.dev" }
    ],
    "tsaUrls" => [
      { "url" => "https://tsa.example/api/v1/timestamp", "majorApiVersion" => 1,
        "validFor" => { "start" => "2025-04-09T00:00:00Z" }, "operator" => "example.dev" }
    ],
    "rekorTlogConfig" => { "selector" => "ANY" },
    "tsaConfig" => { "selector" => "ANY" }
  }.freeze

  def config(raw = STAGING_LIKE)
    Sigstore::SigningConfig.from_json(JSON.dump(raw))
  end

  def test_rejects_unknown_media_type
    raw = STAGING_LIKE.merge("mediaType" => "application/vnd.dev.sigstore.signingconfig.v0.1+json")
    error = assert_raise(Sigstore::Error::InvalidSigningConfig) { config(raw) }
    assert_include error.message, "unsupported signing config format"
  end

  def test_any_selector_prefers_current_highest_version_tlog
    Timecop.freeze(Time.utc(2026, 1, 1)) do
      tlog = config.tlog
      assert_equal "https://log-alpha3.example", tlog.url
      assert_equal 2, tlog.major_api_version
    end
  end

  def test_selects_fulcio_oidc_and_tsa
    Timecop.freeze(Time.utc(2026, 1, 1)) do
      sc = config
      assert_equal "https://fulcio.example", sc.fulcio.url
      assert_equal "https://oauth2.example/auth", sc.oidc_url
      assert_equal ["https://tsa.example/api/v1/timestamp"], sc.tsa_urls
    end
  end

  def test_falls_back_to_v1_tlog_before_v2_window_opens
    # Before the v2 services' validity windows, only the v1 log is valid.
    Timecop.freeze(Time.utc(2024, 1, 1)) do
      tlog = config.tlog
      assert_equal "https://rekor-v1.example", tlog.url
      assert_equal 1, tlog.major_api_version
    end
  end

  def test_raises_when_no_valid_tlog
    raw = STAGING_LIKE.merge(
      "rekorTlogUrls" => [
        { "url" => "https://log.example", "majorApiVersion" => 2,
          "validFor" => { "start" => "2999-01-01T00:00:00Z" }, "operator" => "example.dev" }
      ]
    )
    Timecop.freeze(Time.utc(2026, 1, 1)) do
      assert_raise(Sigstore::Error::InvalidSigningConfig) { config(raw) }
    end
  end

  def test_exact_selector_requires_count
    raw = STAGING_LIKE.merge("rekorTlogConfig" => { "selector" => "EXACT", "count" => 2 })
    Timecop.freeze(Time.utc(2026, 1, 1)) do
      # Only one service survives per-operator collapsing, so EXACT count=2 fails.
      assert_raise(Sigstore::Error::InvalidSigningConfig) { config(raw) }
    end
  end

  def test_exact_selector_missing_count_raises_invalid_signing_config
    # The proto defaults an unset count to 0, which the spec forbids for EXACT.
    raw = STAGING_LIKE.merge("rekorTlogConfig" => { "selector" => "EXACT" })
    Timecop.freeze(Time.utc(2026, 1, 1)) do
      error = assert_raise(Sigstore::Error::InvalidSigningConfig) { config(raw) }
      assert_include error.message, "EXACT selector requires a positive integer count"
    end
  end

  def test_exact_selector_non_numeric_count_raises_invalid_signing_config
    # A non-integer count is rejected when decoding the uint32 proto field.
    raw = STAGING_LIKE.merge("rekorTlogConfig" => { "selector" => "EXACT", "count" => "two" })
    Timecop.freeze(Time.utc(2026, 1, 1)) do
      error = assert_raise(Sigstore::Error::InvalidSigningConfig) { config(raw) }
      assert_include error.message, "invalid signing config"
    end
  end

  def test_exact_selector_rejects_more_services_than_count
    # Two distinct operators each contribute one valid v2 tlog, so the result has two
    # services; EXACT count=1 must reject the over-match rather than truncating to one.
    raw = STAGING_LIKE.merge(
      "rekorTlogUrls" => [
        { "url" => "https://log-a.example", "majorApiVersion" => 2,
          "validFor" => { "start" => "2025-01-01T00:00:00Z" }, "operator" => "a.dev" },
        { "url" => "https://log-b.example", "majorApiVersion" => 2,
          "validFor" => { "start" => "2025-01-01T00:00:00Z" }, "operator" => "b.dev" }
      ],
      "rekorTlogConfig" => { "selector" => "EXACT", "count" => 1 }
    )
    Timecop.freeze(Time.utc(2026, 1, 1)) do
      error = assert_raise(Sigstore::Error::InvalidSigningConfig) { config(raw) }
      assert_include error.message, "Expected 1 services in signing config, found 2"
    end
  end

  def test_exact_selector_accepts_matching_count
    raw = STAGING_LIKE.merge(
      "rekorTlogUrls" => [
        { "url" => "https://log-a.example", "majorApiVersion" => 2,
          "validFor" => { "start" => "2025-01-01T00:00:00Z" }, "operator" => "a.dev" },
        { "url" => "https://log-b.example", "majorApiVersion" => 2,
          "validFor" => { "start" => "2025-01-01T00:00:00Z" }, "operator" => "b.dev" }
      ],
      "rekorTlogConfig" => { "selector" => "EXACT", "count" => 2 }
    )
    Timecop.freeze(Time.utc(2026, 1, 1)) do
      assert_nothing_raised { config(raw) }
    end
  end
end
