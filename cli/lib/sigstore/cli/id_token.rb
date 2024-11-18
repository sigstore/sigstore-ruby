# frozen_string_literal: true

class Sigstore::CLI
  class IdToken
    include Sigstore::Loggable

    class AmbientCredentialError < Sigstore::Error
    end

    def self.detect_credential
      [
        GitHub
        # detect_gcp,
        # detect_buildkite,
        # detect_gitlab,
        # detect_circleci
      ].each do |detector|
        credential = detector.call("sigstore")
        return credential if credential
      end

      logger.debug { "failed to find ambient OIDC credential" }

      nil
    end

    def self.call(audience)
      new(audience).call
    end

    def initialize(audience)
      @audience = audience
    end

    def call
      raise NotImplementedError, "#{self.class}#call"
    end

    class GitHub < IdToken
      class PermissionCredentialError < Sigstore::Error
      end

      def call
        logger.debug { "looking for OIDC credentials" }
        unless ENV["GITHUB_ACTIONS"]
          logger.debug { "environment doesn't look like a GH action; giving up" }
          return
        end

        req_token = ENV.fetch("ACTIONS_ID_TOKEN_REQUEST_TOKEN", nil)
        unless req_token
          raise PermissionCredentialError,
                "missing or insufficient OIDC token permissions, " \
                "the ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable was unset"
        end

        req_url = ENV.fetch("ACTIONS_ID_TOKEN_REQUEST_URL", nil)
        unless req_url
          raise PermissionCredentialError,
                "missing or insufficient OIDC token permissions, " \
                "the ACTIONS_ID_TOKEN_REQUEST_URL environment variable was unset"
        end
        req_url = URI.parse(req_url)
        req_url.query = "audience=#{URI.encode_uri_component(@audience)}"

        logger.debug { "requesting OIDC token" }
        resp = Net::HTTP.get_response(
          req_url, { "Authorization" => "bearer #{req_token}" }
        )

        begin
          resp.value
        rescue Net::HTTPExceptions
          raise AmbientCredentialError, "OIDC token request failed (code=#{resp.code}, body=#{resp.body})"
        rescue Timeout::Error
          raise AmbientCredentialError, "OIDC token request timed out"
        end

        begin
          body = JSON.parse resp.body
        rescue StandardError
          raise AmbientCredentialError, "malformed or incomplete json"
        else
          body.fetch("value")
        end
      end
    end
  end
end
