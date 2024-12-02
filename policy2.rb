# frozen_string_literal: true

require "bundler/setup"
require "kdl"
require "literal"
require "sigstore"
require "sigstore/models"

KDL.parse_document(File.read("policy-schema.kdl"))

class PolicySet < Literal::Struct
  prop :description, _String?
  prop :defs, _Hash(_String, _Any), default: -> { {} }
  prop :policies_by_package_type, _Hash(_String, _Array(_Any)), default: -> { {} }

  def authorize(subject)
    case subject
    when RubygemSubject
      policies = policies_by_package_type["rubygem"]
      relevant_policies = policies.select do |policy|
        policy.name == subject.name
      end

      return { effect: "deny", relevant_policies: } if relevant_policies.empty?

      results = Hash.new { |h, k| h[k] = [] }
      relevant_policies.each do |policy|
        ev = policy.evaluate(subject, self)
        results[ev] << policy
      end
      results
    else
      raise ArgumentError, "Unsupported subject type"
    end
  end
end

class Policy < Literal::Struct
  prop :name, _String
  prop :effect, _Union("allow", "deny"), default: -> { "allow" }
  prop :rules, _Array(_Any), default: -> { [] }

  def evaluate(subject, doc)
    (rules.to_h do |rule|
      [rule, rule.evaluate(subject, doc, {})]
    end.all? { _2 } && effect.to_sym) || :deny
  end
end

class Macro < Literal::Struct
  prop :name, _String
  prop :kwargs, _Hash(_String, _Any), default: -> { {} }
  prop :body, _Array(_Any), default: -> { [] }

  def evaluate(this, doc, kwargs)
    body.to_h do |rule|
      [rule, rule.evaluate(this, doc, kwargs)]
    end
  end

  def self.from_kdl(node)
    case node
    in KDL::Node[ "def", [[name, nil, nil]], props, body ]
      kwargs = props
      new(name: name, kwargs: kwargs, body: body.map { Rule.from_kdl(_1) })
    end
  end
end

class KDL::Document
  def deconstruct
    nodes
  end
end

class KDL::Node
  def deconstruct
    [name, arguments, properties, children]
  end
end

class KDL::Value
  def deconstruct
    [value, format, type]
  end
end

class Rule < Literal::Struct
  def evaluate(this, doc)
    raise NotImplementedError, "#{self.class.name}#evaluate not implemented"
  end

  def self.from_kdl(node, scope = nil)
    case node

    in KDL::Value[value, nil, nil]
      value
    in KDL::Value[value, nil, "var"]
      VarRef.new(name: value)
    in KDL::Node[ "$if", [cond], {}, children ]
      IfRule.new(cond: from_kdl(cond, scope), then: children.map { from_kdl(_1, scope) })
    in KDL::Node[ "$elseif", [cond], {}, children ]
      ElseIfRule.new(cond: from_kdl(cond, scope), then: children.map { from_kdl(_1, scope) })
    in KDL::Node[ "$else", [], {}, children ]
      ElseRule.new(then: children.map { from_kdl(_1, scope) })
    in KDL::Node[ /\A%(.+)/, [], kwargs, [] ]
      MacroCall.new(name: ::Regexp.last_match(1), kwargs: kwargs.transform_values { from_kdl(_1, scope) })
    in KDL::Node[ name, [], {}, children ] unless children.empty?
      n = scoped(scope, name)
      ScopeRule.new(key: name, rules: children.map { from_kdl(_1, n) })
    in KDL::Node[ name, arguments, {}, [] ]
      n = scoped(scope, name)
      KeyValueRule.new(key: n, value: arguments.map { from_kdl(_1, n) })
    end
  end

  def self.scoped(base, part)
    return base if part == "$this"
    return part if base.nil?

    "#{base}.#{part}"
  end
end

class MacroCall < Rule
  prop :name, _String
  prop :kwargs, _Hash(_String, _Any)

  def evaluate(this, doc, kwargs)
    doc.defs.fetch(name).evaluate(this, doc, kwargs)
  end
end

class IfRule < Rule
  prop :cond, _Any
  prop :then, _Array(_Any)

  def evaluate(this, doc, kwargs)
    if cond.evaluate(this, doc, kwargs)
      self.then.all? do |rule|
        rule.evaluate(this, doc, kwargs)
      end
    else
      true
    end
  end
end

class ElseIfRule < Rule
  prop :cond, _Any
  prop :then, _Array(_Any)
end

class ElseRule < Rule
  prop :then, _Array(_Any)
end

class KeyValueRule < Rule
  prop :key, _String
  prop :value, _Any

  def evaluate(this, _doc, _kwargs)
    return value == this if key == "$this"

    this.match_attribute?(key, value)
  rescue Exception => e
    raise ArgumentError, "Failed to match attribute #{key.inspect} with value #{value.inspect} on #{this.inspect}: #{e}"
  end
end

class MacroRule < Rule
  prop :name, _String
  prop :kwargs, _Hash(_String, _Any), default: -> { {} }

  def evaluate(this, doc, kwargs)
    doc.defs.fetch(name).evaluate(this, doc, kwargs)
  end
end

class ScopeRule < Rule
  prop :key, _String
  prop :rules, _Array(_Any)

  def evaluate(this, doc, kwargs)
    rules.all? do |rule|
      rule.evaluate(this, doc, kwargs)
    end
  end
end

class VarRef < Rule
  prop :name, _String

  def evaluate(_this, _doc, kwargs)
    kwargs.fetch(name)
  end
end

PolicySet.new(
  description: "A set of policies",
  defs: {
    "githubAttestation" => Macro.new(
      name: "githubAttestation",
      kwargs: {
        "owner" => "String",
        "repo" => "String"
      },
      body: [
        ScopeRule.new(key: "attestation", rules: [
                        KeyValueRule.new(key: "x509.Issuer", value: "https://token.actions.githubusercontent.com")
                      ])
      ]
    )
  },
  policies_by_package_type: {
    "rubygem" => [
      Policy.new(
        name: "bundler",
        rules: [
          KeyValueRule.new(key: "version", value: ">= 7"),
          KeyValueRule.new(key: "platform", value: "ruby"),
          KeyValueRule.new(key: "source", value: "https://rubygems.org"),
          MacroRule.new(name: "githubAttestation", kwargs: { "owner" => "rubygems", "repo" => "bundler" })
        ]
      )
    ]
  }
)

class HashPattern < Literal::Struct
  prop :pairs, _Array(_Tuple(_String, _Any)), :positional

  def ===(other)
    return unless other.is_a?(Hash)

    other = other.dup
    pairs.each do |key, value|
      return false unless other.key?(key)
      return false unless value === other.delete(key)
    end
    other.empty?
  end

  def self.===(other)
    super || other.is_a?(Hash)
  end
end

ToPattern = lambda { |object, indent = ""|
  case object
  in nil | true | false
    "#{indent}#{object.inspect}"
  in String
    "#{indent}#{object.dump}"
  in Array[*args]
    "#{indent}[\n#{args.map { ToPattern[_1, "#{indent}  "] }.join(",\n#{indent}  ")}\n#{indent}]"
  in Hash[**args]
    "#{indent}{\n#{args.map do |k, v|
      "#{indent}#{k}: #{ToPattern[v, "#{indent}  "].strip}"
    end.join(",\n")}\n#{indent}}"
  in Object
    if object.respond_to?(:deconstruct_keys)
      "#{indent}#{object.class.name}[#{ToPattern[object.deconstruct_keys(nil), "#{indent}  "].strip[1..-2]}]"
    elsif object.respond_to?(:deconstruct)
      "#{indent}#{object.class.name}#{ToPattern[object.deconstruct, "#{indent}  "].strip}"
    else
      object.class.name
    end
  end
}

ToSexp = lambda { |object|
  case object
  in true | false | nil | Integer | Float | Symbol | String
    object
  in Array[*args]
    args.map { ToSexp[_1] }
  in Hash[**args]
    args.transform_values { ToSexp[_1] }
  in Object
    if object.respond_to?(:deconstruct_keys)
      [object.class.name, object.deconstruct_keys(nil).transform_values { ToSexp[_1] }.transform_keys(&ToSexp)]
    elsif object.respond_to?(:deconstruct)
      [object.class.name, object.deconstruct.map { ToSexp[_1] }]
    else
      raise
    end
  end
}

class RubygemSubject < Literal::Struct
  prop :name, _String
  prop :version, Gem::Version
  prop :platform, _Union(Gem::Platform, Gem::Platform::RUBY)
  prop :source, _String

  prop :attestation, _Array(Sigstore::SBundle)

  def match_attribute?(key, value)
    case key
    when "name"
      value === name
    when "version"
      Gem::Requirement.create(value).satisfied_by?(version)
    when "platform"
      value => Array[pl]

      Gem::Platform.new(pl) === platform
    when "source"
      source == value
    when /\Aattestation\.x509\.(.+)/
    else
      raise ArgumentError, "Unknown attribute: #{key}"
    end
  end
end

class Policy
  def self.from_kdl(node)
    name = nil
    effect = "allow"

    node.arguments.each do |arg|
      raise if name

      name = arg.value || raise
    end

    node.properties.each do |key, value|
      case key
      in "effect"
        effect = value.value || raise
      end
    end

    rules = node.children.map do |child|
      Rule.from_kdl(child)
    end

    new(
      name: name,
      effect: effect,
      rules: rules
    )
  end
end

class PolicySet
  def self.from_kdl(doc)
    Literal.check(actual: doc, expected: KDL::Document)

    description = nil
    defs = {}
    policies_by_package_type = Hash.new { |h, k| h[k] = [] }

    doc.nodes.each do |node|
      case node.name
      when "description"
        raise if description

        description = node.arguments[0].value
      when "def"
        raise if defs[node.arguments[0].value]

        defs[node.arguments[0].value] = Macro.from_kdl(node)
      else
        policies_by_package_type[node.name] <<
          Policy.from_kdl(node)
      end
    end

    new(
      description: description,
      defs: defs,
      policies_by_package_type: policies_by_package_type
    )
  end
end

class Compiler
  def initialize
    @source = +"# frozen_string_literal: true\ndef call(subject)\n"
  end

  def compile(node)
    visit(node)
    @source

    # Module.new do
    #   module_eval source
    # end
  end

  def visit(node)
    send("visit_#{node.class.name.gsub("::", "_")}", node)
  end

  def visit_PolicySet(node)
    node.policies_by_package_type.each do |package_type, policies|
      @package_type = package_type
      @source << "  # Policies for #{package_type}\n"
      @source << "  if subject.name == #{package_type.inspect}; while true\n"
      policies.each do |policy|
        visit(policy)
      end
      @source << "  break; end\n"
      @source << "  end\n"
    end
    @source << "end\n"
  end

  def visit_Policy(node)
    @source << "  # Policy #{node.name}\n"
    @source << "  # Effect: #{node.effect}\n"
    node.rules.each do |rule|
      visit(rule)
    end
  end

  def visit_KeyValueRule(node)
    @source << "    break unless subject[#{node.key.inspect}] === #{node.value.inspect}\n"
  end
end

require "test/unit/autorunner"

class T < Test::Unit::TestCase
  def test_parse_doc
    doc = KDL.parse_document <<~KDL
      rubygem "bundler" {
        version "~> 7"
      }
    KDL

    set = PolicySet.from_kdl(doc)
    assert_nothing_raised do
      set => PolicySet[
        description: nil,
        defs: {},
        policies_by_package_type: policies
      ]
      policies["rubygem"] => [
        Policy[
          name: "bundler",
          effect: "allow",
          rules: [
            KeyValueRule[
              key: "version",
              value: ["~> 7"]
            ]
          ]
        ]
      ]
    end

    subject = RubygemSubject.new(
      name: "bundler",
      version: Gem::Version.new("7.0.0"),
      platform: Gem::Platform.new("ruby"),
      source: "https://rubygems.org",
      attestation: []
    )

    set.authorize(subject) => {
      allow: [Policy[name: "bundler"]]
    }
  end

  def test_parse_doc_scope
    doc = KDL.parse_document <<~KDL
      rubygem "bundler" {
        platform {
          $this "ruby"
          $this "ruby"
        }
      }
    KDL

    set = PolicySet.from_kdl(doc)
    assert_nothing_raised do
      set => PolicySet[
       description: nil,
       defs: {},
       policies_by_package_type: policies
     ]
      policies["rubygem"] => [
        Policy[
          name: "bundler",
          effect: "allow",
          rules: [
            ScopeRule[key: "platform", rules: [
            KeyValueRule[
              key: "platform", value: ["ruby"]
            ],
            KeyValueRule[
              key: "platform", value: ["ruby"]
            ]]]
          ]
        ]
      ]
    end
    subject = RubygemSubject.new(
      name: "bundler",
      version: Gem::Version.new("7.0.0"),
      platform: Gem::Platform.new("ruby"),
      source: "https://rubygems.org",
      attestation: []
    )

    set.authorize(subject) => {
      allow: [Policy[name: "bundler"]]
    }
  end

  def test_parse_big
    doc = KDL.parse_document(File.read("policy-schema.kdl"))

    set = PolicySet.from_kdl(doc)

    assert_equal ["PolicySet",
                  { description: "A policy for RubyGems",
                    defs: { "githubAttestation" =>
                      ["Macro",
                       { name: "githubAttestation",
                         kwargs: { "owner" => ["KDL::Value::String", ["string", nil, nil]],
                                   "repository" => ["KDL::Value::String",
                                                    ["string", nil, nil]],
                                   "workflow" => ["KDL::Value::String", ["string", nil, nil]],
                                   "environment" => ["KDL::Value::String",
                                                     ["string?", nil, nil]] },
                         body: [["ScopeRule",
                                 { key: "attestation",
                                   rules: [["KeyValueRule", { key: "attestation.x509.Issuer", value: ["https://token.actions.githubusercontent.com"] }],
                                           ["KeyValueRule",
                                            { key: "attestation.x509.Repository",
                                              value: [["VarRef", { name: "repository" }]] }],
                                           ["KeyValueRule",
                                            { key: "attestation.x509.Workflow",
                                              value: [["VarRef", { name: "workflow" }]] }],
                                           ["IfRule",
                                            { cond: ["VarRef", { name: "environment" }],
                                              then: [["KeyValueRule",
                                                      { key: "attestation.x509.Environment",
                                                        value: [["VarRef",
                                                                 { name: "environment" }]] }]] }],
                                           ["ElseIfRule",
                                            { cond: ["VarRef", { name: "environment" }],
                                              then: [["KeyValueRule",
                                                      { key: "attestation.x509.Environment",
                                                        value: [["VarRef",
                                                                 { name: "environment" }]] }]] }],
                                           ["ElseRule",
                                            { then: [["KeyValueRule",
                                                      { key: "attestation.x509.Environment",
                                                        value: ["production"] }]] }],
                                           ["ScopeRule",
                                            { key: "$oneOf",
                                              rules: [["KeyValueRule", { key: "attestation.$oneOf.messageSignature", value: [] }],
                                                      ["ScopeRule",
                                                       { key: "$all",
                                                         rules: [["KeyValueRule", { key: "attestation.$oneOf.$all.dsseEnvelope.payloadType", value: ["application/vnd.in-toto+json"] }],
                                                                 ["ScopeRule",
                                                                  { key: "dsseEnvelope.payload",
                                                                    rules: [["KeyValueRule", { key: "attestation.$oneOf.$all.dsseEnvelope.payload._type", value: ["https://in-toto.io/Statement/v1"] }],
                                                                            ["KeyValueRule",
                                                                             { key: "attestation.$oneOf.$all.dsseEnvelope.payload.predicateType",
                                                                               value: ["https://slsa.dev/provenance/v1"] }],
                                                                            ["KeyValueRule",
                                                                             {
                                                                               key: "attestation.$oneOf.$all.dsseEnvelope.payload.predicate.buildDefinition.externalParameters.workflow.repository", value: [[
                                                                                 "VarRef", { name: "repository" }
                                                                               ]]
                                                                             }]] }]] }]] }]] }]] }] },
                    policies_by_package_type: { "rubygem" =>
                      [["Policy",
                        { name: "bundler",
                          effect: "allow",
                          rules: [["KeyValueRule", { key: "version", value: [">= 7"] }],
                                  ["KeyValueRule", { key: "platform", value: ["ruby"] }],
                                  ["KeyValueRule",
                                   { key: "source", value: ["https://rubygems.org"] }],
                                  ["MacroCall",
                                   { name: "githubAttestation",
                                     kwargs: { "owner" => "rubygems", "repo" => "bundler",
                                               "workflow" => ".github/workflows/release.yml" } }]] }]] } }], ToSexp[set]

    subject = RubygemSubject.new(
      name: "bundler",
      version: Gem::Version.new("7.0.0"),
      platform: Gem::Platform.new("ruby"),
      source: "https://rubygems.org",
      attestation: []
    )

    set.authorize(subject) => {
      allow: [Policy[name: "bundler"]]
    }
  end
end
