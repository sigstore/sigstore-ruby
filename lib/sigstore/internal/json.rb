# frozen_string_literal: true

module Sigstore::Internal::JSON
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
      "[" + data.map { |v| canonical_generate(v) }.join(",") + "]"
    when Hash
      "{" +
        data.sort_by { |k, _|
          k.encode("utf-16").codepoints
        }.map { |k, v| "#{canonical_generate(k)}:#{canonical_generate(v)}" }.join(",") +
        "}"
    else
      raise ArgumentError, "Unsupported data type: #{data.class}"
    end
  end
end
