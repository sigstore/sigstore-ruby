# frozen_string_literal: true

module Sigstore::Internal
  module ::Util
    module_function

    def hex_encode(string) = string.unpack1("H*")
    def hex_decode(string) = [string].pack("H*")

    def base64_encode(string) = [string].pack("m0")
    def base64_decode(string) = string.unpack1("m0")
  end
end
