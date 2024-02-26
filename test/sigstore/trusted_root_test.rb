# frozen_string_literal: true

require "test_helper"
require "sigstore/trusted_root"

class Sigstore::TrustedRootTest < Test::Unit::TestCase
  def test_production
    VCR.use_cassette("production") do |cassette|
      Timecop.freeze(cassette.originally_recorded_at || Time.now) do
        production = Sigstore::TrustedRoot.production
        assert_equal "application/vnd.dev.sigstore.trustedroot+json;version=0.1", production.media_type
        assert_equal ["0Y0\x13\x06\a*\x86H\xCE=\x02\x01\x06\b*\x86H\xCE=\x03\x01\a\x03B\x00\x04\xD8m\x98\xFBkZm\xD4\xD5\xE4\x17\x06\x88\x121\xD1\xAF_\x00\\+\x90\x16\xE6-!\xAD\x92\xCE\v\xDE\xA5\xFA\xC9\x864\xCE\xE7\xC1\x9E\x10\xBCR\xBF\xE2\xCB\x9EF\x85c\xFF\xF4\x0F\xDBcb\xE1\v}\f\xF7\xE4X\xB7".b],
                     production.rekor_keys
        assert_equal ["0Y0\x13\x06\a*\x86H\xCE=\x02\x01\x06\b*\x86H\xCE=\x03\x01\a\x03B\x00\x04\x88\xF4\xA5\x16-\x02\x98T\xDF\x120\x94\xA8_G\xB8!\x1CasJ\x01\xA6\x1A\x94\x82f\x05\x9F2\xC9\xEC\xCF\x8D:\xA1\xC6\xB2\x81\xA4\xC9\xDA\xA1\xC5m,\x90H\xD5\xE37\xB9y\xD0\xCD\x01\x80%\xD2x\x82\xCFE\xCB".b],
                     production.ctfe_keys
        assert_equal ["-----BEGIN CERTIFICATE-----\nMIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAq\nMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx\nMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUu\nZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSy\nA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0Jcas\ntaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6Nm\nMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE\nFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2u\nSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJx\nVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uup\nHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==\n-----END CERTIFICATE-----\n",
                      "-----BEGIN CERTIFICATE-----\nMIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C\nAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7\n7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS\n0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB\nBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp\nKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI\nzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR\nnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP\nmygUY7Ii2zbdCdliiow=\n-----END CERTIFICATE-----\n",
                      "-----BEGIN CERTIFICATE-----\nMIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7\nXeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex\nX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j\nYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY\nwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ\nKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM\nWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9\nTNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ\n-----END CERTIFICATE-----\n"], production.fulcio_cert_chain.map(&:to_pem)
      end
    end
  end

  def test_production_offline
    production_offline = Sigstore::TrustedRoot.production(offline: true)
    assert_equal "application/vnd.dev.sigstore.trustedroot+json;version=0.1", production_offline.media_type
  end
end
