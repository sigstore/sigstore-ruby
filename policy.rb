# frozen_string_literal: true

require "bundler/setup"
require "kdl"
require "literal"

class KDLVisitor
  def visit(node)
    case node
    when KDL::Node
      visit_node(node)
    when KDL::Value
      visit_value(node)
    when KDL::Document
      visit_document(node)
    else
      raise ArgumentError, "unexpected node type: #{node.class}"
    end
  end

  def visit_document(document)
    document.nodes.each { visit(_1) }
  end

  def visit_node(node)
    visit_arguments(node.arguments)
    visit_properties(node.properties)
    visit_children(node.children)
  end

  def visit_children(children)
    children.each { visit(_1) }
  end

  def visit_arguments(arguments)
    arguments.each { visit(_1) }
  end

  def visit_properties(properties)
    properties.each { |k, v| visit_property(k, v) }
  end

  def visit_property(_key, value)
    visit_value(value)
  end

  def visit_value(value)
    case value
    when KDL::Value::Int
      visit_int(value)
    when KDL::Value::Float
      visit_float(value)
    when KDL::Value::Boolean
      visit_boolean(value)
    when KDL::Value::String
      visit_string(value)
    when KDL::Value::NullImpl
      visit_null(value)
    else
      raise ArgumentError, "unexpected value type: #{value.class}"
    end
  end

  def visit_int(value); end

  def visit_float(value); end

  def visit_boolean(value); end

  def visit_string(value); end

  def visit_null(value); end

  def call(node)
    visit(node)
    self
  end
end

class PolicyParser < KDLVisitor
  def initialize
    super
    @description = nil
    @package_types = {}
    @defs = {}
  end

  def visit_node(node)
    case node.name
    when "description"
    when "rubygem"
      pp RubygemPolicyParser.new.call(node)
    else
      raise ArgumentError, "unexpected top-level node type: #{node.name}"
    end
  end
end

class PropsType
  def initialize(**shape)
    @shape = shape
  end

  def ===(value)
    value.is_a?(Hash) && value.all? do |k, v|
      @shape.any? do |k_type, v_type|
        k_type === k && v_type === v
      end
    end
  end

  def inspect
    @shape.map { |k, v| "#{k.inspect}=#{v.inspect}" }.join(" ")
  end
end

class ExpectKDLNode
  include Literal::Types

  class Children
    def initialize(&blk)
      @children = {}
      instance_eval(&blk) if blk
    end

    def respond_to_missing?(...) = true

    def method_missing(name, ...)
      name = name.name
      raise ArgumentError, "unexpected method: #{name}" if @children[name]

      @children[name] = ExpectKDLNode.new(name, ...)
    end

    def ===(other)
      other.is_a?(KDL::Node) &&
        @children[other.name] === other
    end
  end

  def initialize(name, *args, **kwargs, &)
    @name = name
    @args = args.empty? ? [] : _Tuple(*args)
    @props = PropsType.new(**kwargs.transform_keys(&:to_s))
    @children = Children.new(&)
  end

  def transform(&block)
    @transform = block
    self
  end

  def parent(&block)
    @parent = block
    self
  end

  def on_child(parent, value)
    @parent.call(parent, value)
  end

  def ===(other)
    other.is_a?(KDL::Node) && @name === other.name &&
      @args === other.arguments &&
      @props === other.properties # &&
    # @children === other.children
  end

  def inspect
    "#{@name} #{@args.inspect} #{@props.inspect} #{@children.inspect}"
    # super
  end

  def record_literal_type_errors(context)
    # return
    return unless context.actual.is_a?(KDL::Node)

    context.add_child(label: "name", expected: @name, actual: context.actual.name) unless @name === context.actual.name
    unless @args === context.actual.arguments
      context.add_child(label: "arguments", expected: @args,
                        actual: context.actual.arguments)
    end
    return if @props === context.actual.properties

    context.add_child(label: "properties", expected: @props,
                      actual: context.actual.properties)

    # return if @children === context.actual.children

    # context.add_child(label: "children", expected: @children,
    #                   actual: context.actual.children)
  end

  def call(node, context: nil)
    raise "Cannot call #{inspect} without a transform block" unless @transform

    i = 0
    args = @args.instance_variable_get(:@types)&.map do |type|
      a = type.call(node.arguments[i])
      i += 1
      a
    end
    raise unless i >= node.arguments.size

    props = @props.instance_variable_get(:@shape).each_with_object({}) do |(k, v), h|
      h[k.intern] = v.call(node.properties[k])
    rescue Exception
      raise $!.exception($!.message + "\n\tin #{k.inspect}")
    end

    result = @transform.call(*args, **props)

    node.children.map do |child|
      ct = @children.instance_variable_get(:@children).fetch(child.name)
      ct.on_child result, ct.call(child)
    end

    result
  rescue Exception
    raise $!.exception($!.message + "\n\tin #{inspect}")
    raise
  end
end

class PolicyDocument < Literal::Struct
  prop :description, _String?
  prop :package_types, _Hash(String, _Any), default: -> { {} }
  prop :defs, _Hash(String, _Any), default: -> { {} }

  def self.from_kdl(kdl)
    Literal.check(actual: kdl, expected: KDL::Document)

    kdl.nodes.each_with_object(new) do |node, policy|
      case node.name
      when "description"
        _parse_description(node)
      when "rubygem"
        # policy.package_types["rubygem"] << RubygemPolicy.from_kdl(node)
      when "def"
        d = Def.from_kdl(node)
        policy.defs[d.name] = d
      else
        raise ArgumentError, "unexpected top-level node type: #{node.name}"
      end
    end
  end

  def self._parse_description(node)
    Literal.check(actual: node, expected: ExpectKDLNode.new("description", String))
  end
end

class KDLValueType
  def initialize(value, type = nil)
    @value = value
    @type = type
  end

  def ===(other)
    other.is_a?(KDL::Value) &&
      @value === other.value &&
      @type === other.type
  end
end

class Def < Literal::Struct
  prop :name, String
  prop :props, _Hash(String, _Any)
  prop :body, _Array(KDL::Node)

  extend Literal::Types

  def self.from_kdl(node)
    Literal.check(actual: node,
                  expected: ExpectKDLNode.new("def", KDLValueType.new(String),
                                              **{ String => KDLValueType.new(String) }))

    name = node.arguments[0].value
    props = node.properties.each_with_object({}) do |(k, v), h|
      h[k] = v.value
    end
    body = node.children
    new(name:, props:, body:)
  end

  def pretty_print(pp)
    pp.text "def"
    pp.text " "
    pp.seplist(props, -> { pp.text(" ") }) do |(k, v)|
      pp.text(k)
      pp.text "="
      pp.pp(v)
    end
    return if body.empty?

    pp.group(1, " {", "}") do
      pp.seplist(body, -> { pp.breakable("; ") }) do |node|
        pp.breakable ""
        pp.pp(node)
      end
    end
  end
end

class RubygemPolicyParser < KDLVisitor
  def initialize
    super
    @name = nil
    @requirements = []
    @verb = :permit
    @fallback = false

    @state = :rubygem
  end

  def visit_node(node)
    raise unless @state == :rubygem

    @name = node.arguments
  end
end

class KDLValueTransformer
  def initialize; end

  def call(value)
    value.value
  end
end

class KDLDocumentTransformer
  def initialize(nodes, &block)
    @nodes = nodes
    @block = block
  end

  def call(document)
    context = Literal::TypeError::Context.new
    unless document.is_a?(KDL::Document)
      context.add_child(label: nil, expected: KDL::Document,
                        actual: document) && return
    end

    @block.call(
      document.nodes.map { |node| @nodes.fetch(node.name).call(node, context: context) }
    )
  end
end

class KDLNodeTransformer
  def initialize(
    arguments,
    properties,
    children,
    &block
  )
    @arguments = arguments
    @properties = properties
    @children = children
    @block = block
  end

  def call(node, context: Literal::TypeError::Context.new)
    # context.add_child(label: nil, expected: KDL::Node, actual: node) && return unless node.is_a?(KDL::Node)

    args = @arguments.call(node.arguments, context: context)
    props = @properties.call(node.properties, context: context)
    children = @children.call(node.children, context: context)

    @block.call(args, props, children)
  end
end

class Def < Literal::Struct
  class Type
  end
  prop :name, String
  prop :props, _Hash(String, Type)
  prop :body, _Array(KDL::Node)

  extend Literal::Types

  def self.from_kdl(node)
    Literal.check(actual: node,
                  expected: ExpectKDLNode.new("def", KDLValueType.new(String),
                                              **{ String => KDLValueType.new(String) }))

    name = node.arguments[0].value
    props = node.properties.transform_values(&:value)
    body = node.children
    new(name:, props:, body:)
  end

  def pretty_print(pp)
    pp.text "def"
    pp.text " "
    pp.seplist(props, -> { pp.text(" ") }) do |(k, v)|
      pp.text(k)
      pp.text "="
      pp.pp(v)
    end
    return if body.empty?

    pp.group(1, " {", "}") do
      pp.seplist(body, -> { pp.breakable("; ") }) do |node|
        pp.breakable ""
        pp.pp(node)
      end
    end
  end
end

class Evaluable
  def initialize(receiver)
    @receiver = receiver
  end

  def self.[](receiver)
    new(receiver)
  end
end

class RubygemRule < Literal::Struct
  prop :deny, _Boolean, default: -> { false }
  prop :version, ::Gem::Requirement
  prop :platform, _Nilable(::Gem::Platform)
  prop :source, _String?

  prop :body, Evaluable[{
    attestation: Evaluable[{
      x509: {
        String => _Any?
      },
      messageSignature: {},
      dsse_envelope: {
        payloadType: _String,
        payload: Hash
      }
    }]
  }]
end

class Sip < Literal::Struct
  prop :description, _String?
  prop :defs, _Hash(String, Def), default: -> { {} }
  prop :package_rules, _Hash(String, _Any), default: -> { Hash.new { |h, k| h[k] = [] } }
end

doc = KDL.parse_document(File.read("policy-schema.kdl"))
# pp doc
# pp PolicyDocument.from_kdl(doc)

KDLDocumentTransformer.new(
  {
    "description" => ExpectKDLNode.new("description", KDLValueTransformer.new).transform do |value|
      { "description" => value }
    end,
    "def" => ->(a, _) { { "def" => a.to_s.gsub(/\n{2,}/, "\n") } },
    "rubygem" => ExpectKDLNode.new("rubygem", KDLValueTransformer.new) do
      version(KDLValueTransformer.new).transform { |*version| Gem::Requirement.new(*version) }.parent do |p, version|
        p[:version] = version
      end
      platform(KDLValueTransformer.new).transform { |platform| platform }.parent do |p, platform|
        p[:platform] = platform
      end
      source(KDLValueTransformer.new).transform { |source| source }.parent do |p, source|
        p[:source] = source
      end

      send(:"%githubAttestation",
           owner: KDLValueTransformer.new,
           "repo" => KDLValueTransformer.new,
           workflow: KDLValueTransformer.new).transform do |owner:, repo:, workflow:|
             { owner:, repo:, workflow: }
           end.parent do |p, attestation|
             p[:attestation] = attestation
           end
    end
      .transform do |name|
        { "rubygem" => name }
      end
  }
) do |nodes|
  nodes.each_with_object Sip.new do |node, sip|
    case node.keys
    when ["description"]
      sip.description = node["description"]
    when ["def"]
      sip.defs[nil] = node
    when ->(k) { k.include?("rubygem") }
      sip.package_rules["rubygem"] << node
    else
      raise ArgumentError, "unexpected node type: #{node}"
    end
  end
end.call(doc).tap { pp _1 }
