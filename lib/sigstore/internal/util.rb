# frozen_string_literal: true

module Sigstore
  module Internal
    module Util
      module_function

      def hex_encode(string)
        string.unpack1("H*")
      end

      def hex_decode(string)
        [string].pack("H*")
      end

      def base64_encode(string)
        [string].pack("m0")
      end

      def base64_decode(string)
        string.unpack1("m0")
      end
    end
  end
end
