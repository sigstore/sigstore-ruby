# frozen_string_literal: true

# Copyright 2024 The Sigstore Authors
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

module Sigstore::Internal
  module JSON
    # Implements https://wiki.laptop.org/go/Canonical_JSON
    #
    # TODO: This is a naive implementation. Performance can be improved by
    #       serializing into a buffer instead of concatenating strings.
    def self.canonical_generate(data)
      case data
      when NilClass
        "null"
      when TrueClass
        "true"
      when FalseClass
        "false"
      when Integer
        data.to_s
      when String
        "\"#{data.gsub(/(["\\])/, '\\\\\1')}\""
      when Array
        contents = data.map { |v| canonical_generate(v) }.join(",")
        "[#{contents}]"
      when Hash
        contents = data.sort_by do |k, _|
          raise ArgumentError, "Non-string key in hash" unless k.is_a?(String)

          k.encode("utf-16").codepoints
        end
        contents.map! do |k, v|
          "#{canonical_generate(k)}:#{canonical_generate(v)}"
        end
        "{#{contents.join(",")}}"
      else
        raise ArgumentError, "Unsupported data type: #{data.class}"
      end
    end
  end
end
