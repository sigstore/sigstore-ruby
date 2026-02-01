# frozen_string_literal: true

# Copyright 2026 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "test_helper"
require "sigstore/rekor/client"
require "sigstore/signer"
require "sigstore/tuf"
require "sigstore/version"

class Sigstore::UserAgentTest < Test::Unit::TestCase
  def test_user_agent_constant
    assert_equal "sigstore-ruby/#{Sigstore::VERSION}", Sigstore::USER_AGENT
    assert Sigstore::USER_AGENT.frozen?
  end

  def test_rekor_client_post_sends_user_agent
    client = Sigstore::Rekor::Client.new(url: "https://rekor.sigstore.dev")
    entries = client.log.entries

    # Capture the headers sent to post2
    captured_headers = nil
    session = entries.instance_variable_get(:@session)
    session.define_singleton_method(:post2) do |_path, _body, headers|
      captured_headers = headers
      # Return a mock response with proper base64-encoded body
      encoded_body = Base64.strict_encode64({ "kind" => "hashedrekord", "apiVersion" => "0.0.1" }.to_json)
      response = Object.new
      response.define_singleton_method(:code) { "201" }
      response.define_singleton_method(:content_type) { "application/json" }
      response.define_singleton_method(:body) do
        { "abc123" => { "body" => encoded_body, "logIndex" => 1, "logID" => "abcd",
                        "integratedTime" => 1234 } }.to_json
      end
      response
    end

    entry = Object.new
    def entry.to_json
      "{}"
    end

    entries.post(entry)

    assert_equal Sigstore::USER_AGENT, captured_headers["User-Agent"]
  end

  def test_rekor_client_retrieve_sends_user_agent
    client = Sigstore::Rekor::Client.new(url: "https://rekor.sigstore.dev")
    retrieve = client.log.entries.retrieve

    # Capture the headers sent to post2
    captured_headers = nil
    session = retrieve.instance_variable_get(:@session)
    session.define_singleton_method(:post2) do |_path, _body, headers|
      captured_headers = headers
      # Return a mock response with proper base64-encoded body
      encoded_body = Base64.strict_encode64({ "kind" => "hashedrekord", "apiVersion" => "0.0.1" }.to_json)
      response = Object.new
      response.define_singleton_method(:code) { "200" }
      response.define_singleton_method(:body) do
        [{ "abc123" => { "body" => encoded_body, "logIndex" => 1, "logID" => "abcd",
                         "integratedTime" => 1234 } }].to_json
      end
      response
    end

    retrieve.post({})

    assert_equal Sigstore::USER_AGENT, captured_headers["User-Agent"]
  end

  def test_signer_fetch_cert_sends_user_agent
    # Stub Net::HTTP.post to capture headers
    captured_headers = nil
    original_post = Net::HTTP.method(:post)

    Net::HTTP.define_singleton_method(:post) do |_uri, _body, headers|
      captured_headers = headers
      # Return a mock response
      response = Object.new
      response.define_singleton_method(:code) { "200" }
      response.define_singleton_method(:body) do
        { signedCertificateEmbeddedSct: { chain: { certificates: ["cert"] } } }.to_json
      end
      response
    end

    begin
      # Create a minimal signer to test fetch_cert directly
      signer = Sigstore::Signer.allocate

      # Create mock trusted_root with certificate_authority_for_signing
      ca = Struct.new(:uri).new("https://fulcio.sigstore.dev")
      trusted_root = Object.new
      trusted_root.define_singleton_method(:certificate_authority_for_signing) { ca }
      signer.instance_variable_set(:@trusted_root, trusted_root)

      # Call fetch_cert - it will fail when parsing the cert, but the HTTP request will have been made
      assert_raise(Sigstore::Error::InvalidCertificate) do
        signer.send(:fetch_cert, { credentials: {}, certificateSigningRequest: "" })
      end

      assert_equal Sigstore::USER_AGENT, captured_headers["User-Agent"]
    ensure
      Net::HTTP.define_singleton_method(:post, &original_post)
    end
  end

  def test_tuf_fetch_sends_user_agent
    Dir.mktmpdir do |dir|
      updater = Sigstore::TUF::TrustUpdater.new("https://tuf-repo-cdn.sigstore.dev", true,
                                                metadata_dir: dir, targets_dir: dir)

      user_agent_received = nil

      mock_fetcher = Object.new
      mock_fetcher.define_singleton_method(:request) do |uri, request_class, _last_modified, &block|
        req = request_class.new(uri.respond_to?(:request_uri) ? uri.request_uri : uri.to_s)
        block&.call(req)
        user_agent_received = req["User-Agent"]

        # Return a valid response
        net_http_ok = defined?(Gem::Net::HTTPOK) ? Gem::Net::HTTPOK : Net::HTTPOK
        response = net_http_ok.new("1.1", 200, "OK")
        response.define_singleton_method(:body) { "{}" }
        response.define_singleton_method(:uri=) { |u| @uri = u }
        response.define_singleton_method(:uri) { @uri }
        response
      end

      original_fetcher = Gem::RemoteFetcher.fetcher
      Gem::RemoteFetcher.define_singleton_method(:fetcher) { mock_fetcher }

      begin
        updater.send(:fetch, "https://tuf-repo-cdn.sigstore.dev/root.json")
        assert_equal Sigstore::USER_AGENT, user_agent_received
      ensure
        Gem::RemoteFetcher.define_singleton_method(:fetcher) { original_fetcher }
      end
    end
  end
end
