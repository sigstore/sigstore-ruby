#! /usr/bin/env ruby
# frozen_string_literal: true

require "bundler/setup"
require "literal"
require "paramesan"
require "test/unit/autorunner"
require "kdl"
require "json"

class KDL::Node
  def deconstruct
    [name, arguments, properties, children]
  end
end

class KDL::Value
  def deconstruct
    [value, format, type]
  end

  def deconstruct_keys(_keys)
    { value:, format:, type: }
  end
end

module ASTNode
  def to_ast
    [self.class.name, *to_h.values.map do |value|
      if value.respond_to?(:to_ast)
        value.to_ast
      elsif value.respond_to?(:map) && !value.is_a?(Hash)
        value.map(&:to_ast)
      elsif value.is_a?(Hash)
        value.transform_values do |v|
          if v.respond_to?(:to_ast)
            v.to_ast
          else
            v
          end
        end.to_a
      else
        value
      end
    end]
  end

  def evaluate(context)
    raise NotImplementedError, "#{self.class}#evaluate not implemented"
  end

  def to_s
    raise NotImplementedError, "#{self.class}#to_s not implemented"
  end
end

class LVal < Literal::Struct
  include ASTNode
  class This < LVal
    def evaluate(ctx)
      ctx.this
    end

    def to_s
      "$this"
    end
  end

  class PropertyAccess < LVal
    prop :lhs, LVal
    prop :name, String

    def evaluate(ctx)
      l = lhs.evaluate(ctx)
      l.fetch(name)
    end

    def to_s
      "#{lhs}.#{name}"
    end
  end
end

class RVal < Literal::Struct
  include ASTNode

  class Variable < RVal
    prop :name, String

    def to_s
      "(var)#{name.inspect}"
    end

    def evaluate(ctx)
      ctx.vars.fetch(name)
    end
  end

  class Literal < RVal
    prop :value, _Any

    def to_s
      value.inspect
    end

    def evaluate(_)
      value
    end
  end

  class Presence < RVal
  end

  def self.from_kdl(node)
    case node
    in KDL::Value[value, nil, nil]
      Literal.new(value:)
    in KDL::Value::String[name, nil, "var"]
      Variable.new(name:)
    in KDL::Value::String[pattern, nil, "regex"]
      Literal.new(value: Regexp.new(pattern))
    end
  end
end

class Rule < Literal::Struct
  include ASTNode

  class Scope < Rule
    prop :lhs, LVal
    prop :rules, _Array(Rule)

    def evaluate(ctx)
      this = ctx.this
      ctx.this = lhs.evaluate(ctx)
      rules.each do |rule|
        rule.evaluate(ctx)
      end
    ensure
      ctx.this = this
    end
  end

  class KeyValue < Rule
    prop :key, LVal
    prop :value, RVal

    def evaluate(ctx)
      return if value.evaluate(ctx) === key.evaluate(ctx)

      ctx.add_failure(self)
    end

    def to_s
      "#{key} #{value}"
    end
  end

  class Condition < Rule
    prop :if_then, _Array(_Tuple(LVal, Rule))
    prop :else, _Array(Rule)
  end

  class Call < Rule
    prop :name, String
    prop :props, _Hash(String, RVal)

    def evaluate(ctx)
      vars = ctx.vars.dup
      ctx.vars.merge!(props.transform_values { _1.evaluate(ctx) })
      macro = ctx.policy_set.defs.fetch(name)
      macro.evaluate(ctx)
    ensure
      ctx.vars.replace(vars)
    end
  end

  def self.from_kdl(node)
    case node
    in [/\A[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*\z/ => name, [KDL::Value => v], {}, rules]
      split_name = name.split(".")
      lhs = split_name.reduce(LVal::This.new) do |acc, part|
        LVal::PropertyAccess.new(lhs: acc, name: part)
      end
      KeyValue.new(key: lhs, value: RVal.from_kdl(v))
    in [/\A([a-zA-Z_][a-zA-Z0-9_]*\.)*\$[a-zA-Z_][a-zA-Z0-9_]*\z/ => name, [KDL::Value => v], {}, rules]
      split_name = name.split(".")
      op = split_name.pop.delete_prefix!("$")
      lhs = split_name.reduce(LVal::This.new) do |acc, part|
        LVal::PropertyAccess.new(lhs: acc, name: part)
      end
      Operator.new(lhs:, op:, rhs: RVal.from_kdl(v))
    in [/\A([a-zA-Z_][a-zA-Z0-9_]*\.)*%[a-zA-Z_][a-zA-Z0-9_]*\z/ => name, [], props, rules]
      split_name = name.split(".")
      name = split_name.pop.delete_prefix!("%")
      lhs = split_name.reduce(LVal::This.new) do |acc, part|
        LVal::PropertyAccess.new(lhs: acc, name: part)
      end
      Scope.new(lhs:, rules: [
                  Call.new(name:, props: props.transform_values { RVal.from_kdl(_1) })
                ])
    in [/\A%(.+)/, [], props, []]
      Call.new(name: ::Regexp.last_match(1), props: props.transform_values { RVal.from_kdl(_1) })
    in [/\A\$.+\z/ => op, [lhs, rhs], {}, []]
      Operator.new(lhs: RVal.from_kdl(lhs), op: op.delete_prefix("$"), rhs: RVal.from_kdl(rhs))
    in [name, [], {}, rules] unless rules.empty?
      lhs = name.split(".").reduce(LVal::This.new) do |acc, part|
        LVal::PropertyAccess.new(lhs: acc, name: part)
      end
      Scope.new(lhs:, rules: rules.map { Rule.from_kdl(_1) })
    end
  end

  def deconstruct_in_ctx(ctx)
    {
      **to_h.transform_values { |value| value.respond_to?(:evaluate) ? value.evaluate(ctx) : value }
    }
  end

  class Operator < Rule
    prop :op, String
    prop :lhs, _Union(LVal, RVal)
    prop :rhs, RVal

    def evaluate(ctx)
      l = lhs.evaluate(ctx)
      r = rhs.evaluate(ctx)
      result =
        case op
        when "gt"
          l > r
        when "gte"
          l >= r
        when "lt"
          l < r
        when "lte"
          l <= r
        when "plus"
          l + r
        when "sub"
          l - r
        else
          raise "Unknown operator: #{op}"
        end
      return result if result

      ctx.add_failure(self)
    rescue StandardError => e
      raise e, "#{inspect} #{e.message}"
    end

    def to_s
      if lhs.is_a?(LVal)
        "#{lhs}.#{op} #{rhs}"
      else
        "#{op} #{lhs} #{rhs}"
      end
    end
  end

  class SetVariable < Rule
    prop :name, String
    prop :value, Rule

    def evaluate(ctx)
      ctx.vars[name] = value.evaluate(ctx)
    end
  end
end

class Policy < Literal::Struct
  include ASTNode
  prop :type, String
  prop :name, String

  prop :rules, _Array(Rule)

  def self.from_kdl(node)
    node => [type, [KDL::Value::String[name, _, _]], {}, rules]
    new(type:, name:, rules: rules.map { Rule.from_kdl(_1) })
  end

  def evaluate(ctx)
    return unless type === ctx.this["type"] && name === ctx.this["name"]

    rules.each_with_object(ctx.inside_policy(self)) do |rule, c|
      rule.evaluate(c)
    end
  end
end

class Def < Literal::Struct
  include ASTNode

  prop :name, String
  prop :props, _Hash(String, _Any)
  prop :rules, _Array(Rule)

  def self.from_kdl(node)
    node => ["def", [KDL::Value::String[name, nil, nil]], props, rules]
    props = props.transform_values do |type|
      case type
      in KDL::Value::String[type, nil, nil]
        type
      end
    end
    rules = rules.map do |rule|
      case rule
      in ["$var", [KDL::Value::String[/\A([a-zA-Z][a-zA-Z0-9_]*)\z/, nil, nil]], {}, [rhs]]
        Rule::SetVariable.new(name: ::Regexp.last_match(1), value: Rule.from_kdl(rhs))
      else
        Rule.from_kdl(rule)
      end
    end
    new(name:, props:, rules:)
  end

  def evaluate(ctx)
    props.each do |name, type|
      case type
      when "integer"
        unless ctx.vars[name].is_a?(Integer)
          raise TypeError, "Expected #{name} to be an integer, got #{ctx.vars[name].class}"
        end
      when "integer?"
        if ctx.vars.key?(name) && !ctx.vars[name].is_a?(Integer)
          raise TypeError, "Expected #{name} to be an integer or nil, got #{ctx.vars[name].class}"
        end
      else
        raise TypeError, "Unknown type: #{type.inspect}"
      end
    end

    rules.each do |rule|
      rule.evaluate(ctx)
    end
  end
end

class PolicySet < Literal::Struct
  include ASTNode
  prop :description, _String?
  prop :defs, _Hash(String, _Any)
  prop :policies, _Array(Policy)

  def self.from_kdl(doc)
    description = nil
    defs = {}
    policies = []

    doc.nodes.each do |node|
      case node
      in ["description", [KDL::Value::String[description, _, _]], {}, []]
        # noop
      in ["def", [KDL::Value::String[name, _, _]], _, _]
        defs[name] = Def.from_kdl(node)
      else
        policies << Policy.from_kdl(node)
      end
    end

    new(description:, defs:, policies:)
  end

  def evaluate(subject)
    ctx = Context.new(policy_set: self, this: subject, vars: {})
    policies.each do |policy|
      policy.evaluate(ctx)
    end
    ctx.result
  end

  class Context < Literal::Struct
    prop :policy_set, PolicySet
    prop :this, _JSONData
    prop :vars, _Hash(String, _Any)

    prop :matching_policies, _Hash(Policy, _Hash(String, _Any)), default: -> { {} }

    def result
      failures = matching_policies.reject { |_, z| z.empty? }
      [matching_policies.any? && failures.empty?, failures]
    end

    def inside_policy(policy)
      matching_policies[policy] = {}
      self
    end

    def add_failure(rule)
      matching_policies.to_a.last.last[rule.to_s] = rule.deconstruct_in_ctx(self)
    end
  end
end

class KDLParser
  def self.parse(input)
    parse_document(Input.new(input))
  end

  class Pos
    def initialize(str, start, finish)
      @str = str
      @start = start
      @finish = finish
    end
  end

  class Input
    attr_accessor :pos

    def initialize(str)
      @str = str
      @pos = 0
      @length = str.length
    end

    def eof?
      @pos >= @length
    end

    def skip_whitespace
      @pos += 1 while @pos < @length && @str[@pos].match?(/\s/)
    end

    def eat_identifer
      start = @pos
      @pos += 1 while @pos < @length && @str[@pos].match?(/\w/)
      @str[start...@pos]
    end
  end

  def initialize(input)
    @input = input
  end

  class << self
    def parse_document(input)
      description = nil
      defs = {}
      policies = []

      loop do
        break if input.eof?

        input.skip_whitespace

        if desc = parse_description(input)
          description = desc
        elsif _def = parse_def(input)
          defs[_def.name] = _def
        else
          policies << parse_policy(input)
        end
      end

      PolicySet.new(description:, defs:, policies:)
    end

    def parse_description(input)
      pos = input.pos
      if input.eat_identifer == "description"
        parse_string(input)
      else
        (
              input.pos = pos
              nil
            )
      end
    end

    def parse_def(input)
      input.pos
      return unless input.skip_whitespace
      return unless input.skip_whitespace == "{"

      parse_hash(input)
    end

    def parse_policy(input)
      input.pos
      return unless input.eat_identifer
      return unless input.skip_whitespace == "{"

      parse_hash(input)
    end
  end
end

class T < Test::Unit::TestCase
  include Paramesan

  param_test [
    [%(description "foo"), ["PolicySet", "foo", [], []]],
    [%(rubygem "bundler" {}), ["PolicySet", nil, [], [["Policy", "rubygem", "bundler", []]]]],
    [%(rubygem "bundler" { version.major.$gt "7" }),
     ["PolicySet", nil, [], [
       ["Policy", "rubygem", "bundler", [
         ["Rule::Operator",
          "gt",
          ["LVal::PropertyAccess", ["LVal::PropertyAccess", ["LVal::This"], "version"], "major"],
          ["RVal::Literal", "7"]]
       ]]
     ]]]
  ] do |input, expected|
    doc = KDL.parse_document(input)
    policy_set = PolicySet.from_kdl(doc)
    assert_equal(expected, policy_set.to_ast)
  end

  File.read("policy-tests.kdl").then do |content|
    doc = KDL.parse_document(content)
    doc.nodes.each do |node|
      node => ["test", [KDL::Value::String[name, _, _]], {}, body]
      test name do
        policy_set = document = nil

        body.each do |child|
          case child
          in ["document", [], {}, nodes]
            document = KDL::Document.new(nodes)
            policy_set = PolicySet.from_kdl(document)
          in ["ast", [KDL::Value::String[ast, _, _]], {}, _]
            assert_equal(eval(ast), policy_set.to_ast)
          in ["example", [], {}, body]
            subject = {}
            match = nil
            determining_rules = []

            body.each do |rule|
              case rule
              in ["subject", [KDL::Value::String[json, _, nil]], {}, []]
                subject = JSON.parse(json)
              in ["match", [KDL::Value::Boolean[match, _, _]], {}, determining_rules]
                # noop
              end
            end

            actual, = assert_nothing_raised { policy_set.evaluate(subject) }

            require "pp"
            assert_equal(match, actual, { policy_set: policy_set.to_ast, subject:, determining_rules: }.pretty_inspect)
            # assert_equal(determining_rules, failures.transform_values(&:to_s).to_a,
            #              { policy_set: policy_set, subject:, match: }.pretty_inspect)
          end
        end

        assert_equal(policy_set.to_ast, KDLParser.parse(document.to_s))
      end
    end
  end
end
