# frozen_string_literal: true

require "test_helper"
require "sigstore/cedar"

class Sigstore::CedarIntegrationTest < Test::Unit::TestCase
  class IntegrationJSON < Data.define(:policies, :entities, :schema, :should_validate, :requests)
    def self.from_json(json)
      new(
        policies: json.fetch("policies"),
        entities: json.fetch("entities"),
        schema: json.fetch("schema"),
        should_validate: json.fetch("shouldValidate"),
        requests: json.fetch("requests").map { |r| Request.from_json(r) }
      )
    end
  end

  class Request < Data.define(:description, :principal, :action, :resource, :context, :validateRequest, :decision,
                              :reason, :errors)
    def self.from_json(json)
      new(
        description: json.fetch("description"),
        principal: json.fetch("principal"),
        action: json.fetch("action"),
        resource: json.fetch("resource"),
        context: json.fetch("context"),
        validateRequest: json.fetch("validateRequest", nil),
        decision: json.fetch("decision"),
        reason: json.fetch("reason"),
        errors: json.fetch("errors")
      )
    end

    def authorization_request
      Sigstore::Cedar::AuthorizationRequest.from_json({
                                                        "principal" => principal,
                                                        "action" => action,
                                                        "resource" => resource,
                                                        "context" => context
                                                      })
    end
  end

  def do_tests(policies, entities, requests)
    policy_set = nil
    assert_nothing_raised(policies) do
      policy_set = Sigstore::Cedar::PolicySet.parse(policies)
    end
    entities = Sigstore::Cedar::Authorizer::Entities.new(JSON.parse(entities).map do |e|
      Sigstore::Cedar::Entity.from_json(e)
    end)

    authorizer = Sigstore::Cedar::Authorizer.new(policy_set:, entities:)

    requests.each do |req|
      actual = nil
      assert_nothing_raised(policies) do
        actual = authorizer.authorize(req.authorization_request)
      end
      determining_policies = req.reason.map do |r|
        if r =~ /\Apolicy(\d+)\z/
          policy_set.static_policies[::Regexp.last_match(1).to_i]
        else
          r
        end
      end
      error_conditions = req.errors.to_h do |e|
        if e =~ /\Apolicy(\d+)\z/
          policy = policy_set.static_policies[::Regexp.last_match(1).to_i]
          [policy, actual.error_conditions[policy]]
        else
          [e, nil]
        end
      end
      expected = Sigstore::Cedar::AuthorizationResponse.new(
        verb: req.decision, determining_policies:, error_conditions:
      )
      assert_equal(expected, actual, "#{req.description}\n\n#{policies}\n\n#{JSON.pretty_generate(req.to_h)}")
    end
  end

  base = File.expand_path("../cedar-integration-tests", __dir__)
  Dir[File.join(base, "tests/**/*.json")].each do |file|
    test "integration test #{file}" do
      contents = JSON.parse(File.read(file))
      contents = IntegrationJSON.from_json(contents)

      do_tests(
        File.read(File.join(base, contents.policies)),
        File.read(File.join(base, contents.entities)),
        contents.requests
      )
    end
  end

  require "rubygems/package"
  fs = {}

  File.open(File.expand_path("../cedar-integration-tests/corpus-tests.tar.gz", __dir__), "rb") do |f|
    Zlib::GzipReader.wrap(f) do |gz|
      Gem::Package::TarReader.new(gz) do |tar|
        tar.each do |entry|
          fs[entry.full_name] = entry.read.force_encoding(Encoding::UTF_8)
        end
      end
    end
  end

  fs.each do |name, content|
    next unless name.match?(%r{/[0-9a-f]{40}\.json\z})

    test "corpus test #{name}" do
      contents = JSON.parse(content)
      contents = IntegrationJSON.from_json(contents)

      do_tests(
        fs.fetch(contents.policies),
        fs.fetch(contents.entities),
        contents.requests
      )
    end
  end

  test "condition" do
    str = 'when { resource.name == "foo" }'
    parser = Sigstore::Cedar::PolicyParser.new(str)
    res = parser.parse_condition

    assert_predicate parser.instance_variable_get(:@scanner).rest, :empty?
    refute_nil res

    str = "when { !context.authenticated }"
    parser = Sigstore::Cedar::PolicyParser.new(str)
    res = parser.parse_condition

    assert_predicate parser.instance_variable_get(:@scanner).rest, :empty?
    refute_nil res
    assert_equal "when{!context.authenticated}\n", res.pretty_inspect
  end

  test "uid hash" do
    uid1 = Sigstore::Cedar::Entity::UID.new(type: "foo", id: "bar")
    uid2 = Sigstore::Cedar::Entity::UID.new(type: "foo", id: "baz")
    uid3 = Sigstore::Cedar::Entity::UID.new(type: "foo", id: "bar")

    h = {
      uid1 => 1,
      uid2 => 2
    }

    assert_equal 1, h[uid1]
    assert_equal 2, h[uid2]
    assert_equal 1, h[uid3]
  end

  test "string like" do
    [
      ["foo", "foo", true],
      [" ", " ", true],
      [" ", "  ", false],
      ["foo", "f*", true],
      [" ", "* *", true],
      ["\0", "\0", true],
      ["\0", "*", true],
      ["\u0000\u0000   ", "\u0000* **  *", true]
    ].each do |lhs, rhs, expected|
      like = Sigstore::Cedar::Policy::JsonExpr::BinaryOp.new(
        op: Sigstore::Cedar::Policy::JsonExpr::BinaryOp::Op::Like,
        lhs: Sigstore::Cedar::Policy::JsonExpr::Value.new(value: lhs),
        rhs: Sigstore::Cedar::Policy::JsonExpr::Value.new(value: rhs)
      )

      result = like.evaluate(nil, nil)
      assert_equal expected, result, "#{like.pretty_inspect} should be #{expected}"
    end
  end
end
