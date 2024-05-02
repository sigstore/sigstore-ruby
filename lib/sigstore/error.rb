# frozen_string_literal: true

module Sigstore
  class Error < StandardError
    class InvalidSignature < Error; end
    class InvalidBundle < Error; end
    class InvalidCertificate < Error; end
    class NoCertificate < Error; end
    class NoTrustedRoot < Error; end
    class NoBundle < Error; end
    class NoSignature < Error; end

    class MissingRekorEntry < Error; end
    class InvalidRekorEntry < Error; end

    class Unimplemented < Error; end

    class UnsupportedPlatform < Error; end
  end
end
