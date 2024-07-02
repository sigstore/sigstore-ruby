# frozen_string_literal: true

require "test_helper"
require "sigstore/internal/json"

class Sigstore::Internal::JSONTest < Test::Unit::TestCase
  def test_canonical_generate
    e = assert_raise(ArgumentError) do
      Sigstore::Internal::JSON.canonical_generate({
                                                    "foo" => [1.2]
                                                  })
    end
    assert_equal "Unsupported data type: Float", e.message

    e = assert_raise(ArgumentError) do
      Sigstore::Internal::JSON.canonical_generate({ 1 => [] })
    end
    assert_equal "Non-string key in hash", e.message

    hash = {
      "empty" => "",
      "a" => "b",
      "null" => nil,
      "true" => true,
      "false" => false,
      "int" => 1,
      "array" => [1, 2, 3, "4"],
      "empty_hash" => {},
      "empty_array" => [],
      "newline_string" => "a\nb\n",
      "quote_string" => "a\"b",
      "hash" => { "c" => "d", "e" => "f" }
    }
    assert_equal <<~JSON.chomp, Sigstore::Internal::JSON.canonical_generate(hash)
      {"a":"b","array":[1,2,3,"4"],"empty":"","empty_array":[],"empty_hash":{},"false":false,"hash":{"c":"d","e":"f"},"int":1,"newline_string":"a
      b
      ","null":null,"quote_string":"a\\"b","true":true}
    JSON
  end
end
