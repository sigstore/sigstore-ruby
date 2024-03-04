# frozen_string_literal: true

module Sigstore
  module Internal
    module Debug
      def debug(*args, **kwargs)
        return unless ENV["SIGSTORE_DEBUG"]

        puts(*args, **kwargs)
      end
    end
  end
end
