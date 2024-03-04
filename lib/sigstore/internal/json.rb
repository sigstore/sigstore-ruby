# frozen_string_literal: true

module Sigstore::Internal::JSON
  # Implements https://wiki.laptop.org/go/Canonical_JSON
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
