# frozen_string_literal: true

require "literal"

class Literal::DataStructure
  alias eql? ==
end

module Sigstore
  class Cedar
    class Error < StandardError
    end

    class Entity < Literal::Struct
      class UID < Literal::Data
        prop :type, String
        prop :id, String

        def self.from_json(json)
          new(
            type: json.fetch("type"),
            id: json.fetch("id")
          )
        end

        def to_s
          "#{type}::#{id.inspect}"
        end

        def pretty_print(q) # rubocop:disable Naming/MethodParameterName
          q.text(to_s)
        end

        def hash
          [@type, @id].hash
        end
      end

      prop :uid, UID
      prop :parents, _Array(UID), default: [].freeze
      prop :attrs, _Hash(String, _JSONData), default: {}.freeze
      prop :tags, _Array(String), default: [].freeze

      def self.from_json(json)
        new(
          uid: UID.from_json(json.fetch("uid")),
          parents: json.fetch("parents").map { UID.from_json(_1) },
          attrs: json.fetch("attrs"),
          tags: json.fetch("tags", [])
        )
      end
    end

    class AuthorizationRequest < Literal::Struct
      prop :principal, Entity::UID
      prop :action, Entity::UID
      prop :resource, Entity::UID
      prop :context, _Hash(String, _Any)

      def self.from_json(json)
        new(
          principal: Entity::UID.from_json(json.fetch("principal")),
          action: Entity::UID.from_json(json.fetch("action")),
          resource: Entity::UID.from_json(json.fetch("resource")),
          context: expand_context(json.fetch("context"))
        )
      end

      def self.expand_context(context)
        case context
        when Hash
          if context.size == 1 && context.key?("__extn")
            extn = context.fetch("__extn")
            Policy::JsonExpr::Function.new(name: extn.fetch("fn"),
                                           args: [Policy::JsonExpr::Value.new(value: extn.fetch("arg"))])
                                      .evaluate(nil, nil)
          elsif context.size == 2 && context.key?("id") && context.key?("type")
            Entity::UID.from_json(context)
          else
            context.transform_values! { expand_context(_1) }
            context
          end
        else
          context
        end
      end
    end

    class AuthorizationResponse < Literal::Struct
      prop :verb, _Union("allow", "deny", "error")

      prop :determining_policies, _Array(->(arg) { arg&.is_a?(Policy) })
      prop :error_conditions, _Hash(->(arg) { arg&.is_a?(Policy) }, _Nilable(_Any))
    end

    class Authorizer < Literal::Struct
      class Entities < Literal::Struct
        prop :list, _Array(Entity), :positional

        def after_initialize
          @by_uid = list.each_with_object({}) { |entity, by_uid| by_uid[entity.uid] = entity }
        end

        def in?(lhs:, rhs:)
          Literal.check(actual: lhs, expected: Entity::UID)
          Literal.check(actual: rhs, expected: Entity::UID)

          return true if lhs == rhs

          seen = Set.new
          seen << lhs
          queue = [lhs]

          while (current = queue.shift)
            return true if current == rhs

            entity = @by_uid[current] || next
            entity.parents.each do |parent|
              next unless seen.add?(parent)

              queue << parent
            end
          end

          false
        end

        def is?(lhs:, type:)
          Literal.check(actual: lhs, expected: Entity::UID)
          Literal.check(actual: type, expected: String)

          lhs.type == type
        end

        def fetch(uid)
          @by_uid.fetch(uid) do
            Entity.new(uid:, parents: [], attrs: {}, tags: [])
          end
        end
      end
      prop :policy_set, ->(arg) { arg&.is_a?(PolicySet) }
      prop :entities, Entities

      def authorize(request)
        Literal.check(actual: request, expected: AuthorizationRequest)

        relevant_policies = policy_set.static_policies.each_with_object(Hash.new do |h, k|
          h[k] = []
        end) do |statement, relevant|
          satisfies = statement.satisfies(request, entities)
          next if satisfies == false

          relevant[satisfies] << statement
        end

        verb = if relevant_policies.empty? || relevant_policies[true].any? { _1.effect != Policy::Effect::Permit }
                 relevant_policies[true].delete_if { _1.effect == Policy::Effect::Permit }
                 "deny"
               elsif relevant_policies.keys != [true]
                 "deny"
               else
                 "allow"
               end

        determining_policies = relevant_policies[true]
        relevant_policies.delete(true)

        AuthorizationResponse.new(
          verb:,
          determining_policies:,
          error_conditions: relevant_policies.flat_map { |k, v| v.map { [_1, k.message] } }.to_h
        )
      end
    end

    class Policy < Literal::Struct
      module JsonExpr
        if false # rubocop:disable Lint/LiteralAsCondition
          def self.included(base)
            base.prepend(Module.new do
              def evaluate(...)
                super.tap { pp(self => _1) }
              end
            end)
          end
        end

        Entity::UID.class_eval do
          include JsonExpr

          def evaluate(_, entities)
            entities.fetch(self)
          end
        end

        # Value = new(_Any)
        class Value < Literal::Struct
          include JsonExpr

          prop :value, _Union(_Array(JsonExpr), String, Integer, _Hash(String, JsonExpr), _Boolean)

          def evaluate(...)
            case value
            when Array
              value.map { _1.evaluate(...) }
            when Hash
              value.transform_values { _1.evaluate(...) }
            else
              value
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            case value
            when Array
              q.group(0, "[", "]") do
                q.seplist(value) { q.pp(_1) }
              end
            when Hash
              q.group(0, "{", "}") do
                q.seplist(value) do |k, v|
                  q.pp(k)
                  q.text(": ")
                  q.pp(v)
                end
              end
            else
              q.text(JSON.generate(value))
            end
          end
        end

        class Var < Literal::Enum(String)
          include JsonExpr

          Principal = new("principal")
          Action = new("action")
          Resource = new("resource")
          Context = new("context")

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text(value)
          end

          def evaluate(parc, entities)
            case value
            in "principal"
              parc.principal.evaluate(parc, entities)
            in "action"
              parc.action.evaluate(parc, entities)
            in "resource"
              parc.resource.evaluate(parc, entities)
            in "context"
              parc.context
            end
          end
        end

        class Slot < Literal::Enum(String)
          Principal = new("?principal")
          Resource = new("?resource")
        end

        # Unknown = new(_Never)
        # Neg = new(JsonExpr)
        # BinaryOp = new(_Tuple(String, JsonExpr, JsonExpr))
        class BinaryOp < Literal::Struct
          include JsonExpr

          class Op < Literal::Enum(String)
            Add = new("+")
            Sub = new("-")
            Mul = new("*")
            Div = new("/")
            Lt = new("<")
            Le = new("<=")
            Gt = new(">")
            Ge = new(">=")
            Eq = new("==")
            Ne = new("!=")
            And = new("&&")
            Or = new("||")
            In = new("in")
            Like = new("like")
          end
          prop :op, Op
          prop :lhs, JsonExpr
          prop :rhs, JsonExpr

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.group(0, "(", ")") do
              q.pp(lhs)
              q.text(" ")
              q.text(op.value)
              q.text(" ")
              q.pp(rhs)
            end
          end

          def evaluate(parc, entities)
            lhs = self.lhs.evaluate(parc, entities)

            case [lhs, op]
            in true, Op::Or
              return true
            in false, Op::And
              return false
            in false, Op::Or
              rhs = self.rhs.evaluate(parc, entities)
              Literal.check(actual: rhs, expected: Literal::Types::BooleanType)
              return rhs
            in true, Op::And # rubocop:disable Lint/DuplicateBranch
              rhs = self.rhs.evaluate(parc, entities)
              Literal.check(actual: rhs, expected: Literal::Types::BooleanType)
              return rhs
            else
              # rhs needs to evaluate
            end

            rhs = self.rhs.evaluate(parc, entities)

            case [lhs, op, rhs]
            in Integer, Op::Le | Op::Lt | Op::Gt | Op::Ge, Integer
              lhs.public_send(op.value, rhs)
            in Integer, Op::Add | Op::Sub | Op::Mul, Integer
              result = lhs.public_send(op.value, rhs)
              raise RangeError, "#{result} (#{lhs} #{op.value} #{rhs}) out of bounds" unless result.bit_length < 64

              result
            in l, Op::Eq | Op::Ne, r if l.instance_of?(r.class)
              l.public_send(op.value, r)
            in IPAddr, Op::Eq, String
              lhs.to_s == rhs
            in _, Op::Eq, _
              false
            in _, Op::Ne, _
              true
            in Entity, Op::In, Entity
              entities.in?(lhs: lhs.uid, rhs: rhs.uid)
            in String, Op::Like, String
              parts = rhs.scan(/(?:[^\\*]|\\\*)+|\*/)
              parts.map! do |part|
                case part
                when "*"
                  ".*"
                when '\*'
                  part
                else
                  Regexp.escape(part)
                end
              end
              pattern = "\\A#{parts.join}\\z"
              Regexp.new(pattern).match?(lhs)
            in Entity, Op::In, Array
              rhs.reduce(false) do |acc, elem|
                Literal.check(actual: elem, expected: Entity)
                acc && entities.in?(lhs: lhs.uid, rhs: elem.uid)
              end
            else
              raise Error,
                    "BinaryOp#evaluate not implemented for #{lhs.class} #{op.value} #{rhs.class}\n" \
                    "#{{ lhs:, rhs:, left: self.lhs, right: self.rhs }.inspect}"
            end
          end
        end

        class Dot < Literal::Struct
          include JsonExpr

          prop :left, JsonExpr
          prop :attr, String

          def evaluate(parc, entities)
            left = self.left.evaluate(parc, entities)

            case left
            when Entity
              result = left.attrs.fetch(attr) { raise Error, "Unknown attribute\n\t#{attr} not in #{left.uid}" }
              if result.is_a?(Hash)
                if result.size == 2 && result.key?("id") && result.key?("type")
                  uid = Entity::UID.from_json(result)
                  entities.fetch(uid)
                else
                  result
                end
              else
                result
              end
            when Hash
              left.fetch(attr) { raise Error, "Unknown attribute\n\t#{attr} not in #{left.keys}" }
            else
              raise Error, "Dot#evaluate not implemented for #{left.class}\n#{pretty_inspect}"
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.pp(left)
            if /\A[a-zA-Z_][a-zA-Z0-9_]*\z/.match?(attr)
              q.text(".")
              q.text(attr)
            else
              q.text("[")
              q.pp(attr)
              q.text("]")
            end
          end
        end

        class Has < Literal::Struct
          include JsonExpr

          prop :left, JsonExpr
          prop :attr, String

          def evaluate(...)
            left = self.left.evaluate(...)

            case left
            when Entity
              left.attrs.key?(attr)
            when Hash
              left.key?(attr)
            else
              raise Error, "Has#evaluate not implemented for #{left.class}\n#{pretty_inspect}"
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.pp(left)
            q.text(" has ")
            q.pp(attr)
          end
        end

        # Has = new(String)
        # Like = new(String)
        # IfThenElse = new(_Tuple(JsonExpr, JsonExpr, JsonExpr))
        # Set = new(String)
        # Record = new(String)

        class Function < Literal::Struct
          include JsonExpr

          prop :name, String
          prop :args, _Array(JsonExpr)

          def evaluate(parc, entities)
            receiver, *args = @args.map { _1.evaluate(parc, entities) }

            case [receiver, name]
            in [Array, "contains"]
              raise ArgumentError, "Expected 1 arguments, got #{args}" unless args.size == 1

              arg = args.first
              case arg
              when Entity
                receiver.any? { entities.in?(lhs: arg.uid, rhs: Entity::UID.from_json(_1)) }
              else
                receiver.include?(args.first)
              end
            in [String, "decimal"]
              raise ArgumentError, "Expected 0 arguments, got #{args}" unless args.empty?

              raise Error, "Invalid decimal: #{receiver}" unless receiver.match?(/\A[+-]?[0-9]+(\.[0-9]+)\z/)

              Rational(receiver)
            in [String, "ip"]
              raise ArgumentError, "Expected 0 arguments, got #{args}" unless args.empty?

              IPAddr.new(receiver)
            in [Rational, "greaterThan"]
              raise ArgumentError, "Expected 1 arguments, got #{args}" unless args.size == 1

              arg = args.first
              Literal.check(actual: arg, expected: Rational)
              receiver > Rational(arg)
            in [Rational, "greaterThanOrEqual"]
              raise ArgumentError, "Expected 1 arguments, got #{args}" unless args.size == 1

              arg = args.first
              receiver >= Rational(arg)
            in [Rational, "lessThan"]
              raise ArgumentError, "Expected 1 arguments, got #{args}" unless args.size == 1

              arg = args.first
              receiver < Rational(arg)
            in [Rational, "lessThanOrEqual"]
              raise ArgumentError, "Expected 1 arguments, got #{args}" unless args.size == 1

              arg = args.first
              receiver <= Rational(arg)
            in [IPAddr, "isLoopback"]
              raise ArgumentError, "Expected 0 arguments, got #{args}" unless args.empty?

              receiver.loopback?
            in [IPAddr, "isMulticast"]
              raise ArgumentError, "Expected 0 arguments, got #{args}" unless args.empty?

              case receiver.family
              when Socket::AF_INET
                IPAddr.new("224.0.0.0/4").include?(receiver)
              else
                false
              end
            in [IPAddr, "isInRange"]
              raise ArgumentError, "Expected 1 arguments, got #{args}" unless args.size == 1

              arg = args.first
              Literal.check(actual: arg, expected: IPAddr)
              arg.include?(receiver)
            else
              raise Error, "Function#evaluate not implemented for #{receiver.class}.#{name}\n" \
                           "#{pretty_inspect}\n#{receiver.inspect}\n#{@args[0].inspect}"
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            receiver, *args = @args
            q.pp(receiver)
            q.text(".")
            q.text(name)
            q.group(0, "(", ")") do
              q.seplist(args) { q.pp(_1) }
            end
          end
        end

        class IfThenElse < Literal::Struct
          include JsonExpr

          prop :cond, JsonExpr
          prop :then, JsonExpr
          prop :else, JsonExpr

          def evaluate(...)
            c = cond.evaluate(...)
            if c.is_a?(TrueClass)
              @then.evaluate(...)
            elsif c.is_a?(FalseClass)
              @else.evaluate(...)
            else
              raise Error, "if condition must be a boolean, not #{c.class}\n\t#{c.inspect}"
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.group(0, "(", ")") do
              q.text("if ")
              q.pp(cond)
              q.text(" then ")
              q.pp(@then)
              q.text(" else ")
              q.pp(@else)
            end
          end
        end

        class Neg < Literal::Struct
          include JsonExpr

          prop :expr, JsonExpr

          def evaluate(...)
            value = expr.evaluate(...)
            case value
            when Integer
              raise RangeError, "#{-value} [-(#{expr})] out of bounds" unless (-value).bit_length < 64

              -value
            else
              raise Error, "Neg#evaluate not defined for #{value.class}\n\t#{value.inspect}"
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("-")
            q.pp(expr)
          end
        end

        class Not < Literal::Struct
          include JsonExpr

          prop :expr, JsonExpr

          def evaluate(...)
            value = expr.evaluate(...)
            case value
            when TrueClass, FalseClass
              !value
            else
              raise Error, "Not#evaluate not defined for #{value.class}\n\t#{value.inspect}"
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("!")
            q.pp(expr)
          end
        end

        class Is < Literal::Struct
          include JsonExpr
          prop :left, JsonExpr
          prop :entity_type, String
          prop :in, _Nilable(JsonExpr)

          def evaluate(parc, entities)
            left = self.left.evaluate(parc, entities)

            case left
            when Entity
              return false unless entities.is?(lhs: left.uid, type: entity_type)

              if @in
                in_ = @in.evaluate(parc, entities)
                raise Error, "in must evaluate to an array" unless in_.is_a?(Array)

                in_.any? { entities.in?(lhs: left.uid, rhs: Entity::UID.from_json(_1)) }
              else
                true
              end
            else
              raise Error, "Is#evaluate not implemented for #{left.class}\n#{pretty_inspect}"
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.pp(left)
            q.text(" is ")
            q.text(entity_type)
            return unless @in

            q.text(" in ")
            q.pp(@in)
          end
        end

        def evaluate(...)
          raise Error, "#{self.class.name}#evaluate not implemented, called on #{inspect}"
        end
      end

      class Effect < Literal::Enum(String)
        Permit = new("permit")
        Forbid = new("forbid")
      end

      module Principal
        class All
          include Principal
          def satisfies?(_, _) = true
          def pretty_print(q) = q.text("principal") # rubocop:disable Naming/MethodParameterName
        end
        ALL = All.new.freeze

        class Eq < Literal::Struct
          include Principal
          prop :ref, Entity::UID

          def satisfies?(parc, _)
            parc.principal == ref
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("principal = ")
            q.pp(ref)
          end
        end

        class In < Literal::Struct
          include Principal
          prop :ref, Entity::UID

          def satisfies?(parc, entities)
            entities.in?(lhs: parc.principal, rhs: ref)
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("principal in ")
            q.pp(ref)
          end
        end

        class Is < Literal::Struct
          include Principal
          prop :type, String
          prop :ref, _Nilable(Entity::UID)

          def satisfies?(parc, entities)
            return false unless entities.is?(lhs: parc.principal, type:)

            if ref
              entities.in?(lhs: parc.principal, rhs: ref)
            else
              true
            end
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("principal is ")
            q.text(type)
            return unless ref

            q.text(" in ")
            q.pp(ref)
          end
        end

        def self.from_json(json)
          case json.fetch("op")
          when "All"
            All
          else
            Principal[json.fetch("op")]
          end
        end
      end

      module Action
        class All
          include Action
          def satisfies?(_, _) = true
          def pretty_print(q) = q.text("action") # rubocop:disable Naming/MethodParameterName
        end
        ALL = All.new.freeze
        class Eq < Literal::Struct
          include Action
          prop :ref, Entity::UID
          def satisfies?(parc, _)
            parc.action == ref
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("action = ")
            q.pp(ref)
          end
        end

        class In < Literal::Struct
          include Action
          prop :refs, _Array(Entity::UID)

          def satisfies?(parc, entities)
            refs.any? { entities.in?(lhs: parc.action, rhs: _1) }
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("action in ")
            q.group(0, "[", "]") do
              q.seplist(refs) { q.pp(_1) }
            end
          end
        end

        def self.from_json(json)
          case json.fetch("op")
          when "All"
            All
          else
            Action[json.fetch("op")]
          end
        end
      end

      module Resource
        class All
          include Resource
          def satisfies?(_, _) = true
          def pretty_print(q) = q.text("resource") # rubocop:disable Naming/MethodParameterName
        end
        ALL = All.new.freeze
        class Eq < Literal::Struct
          include Resource
          prop :ref, Entity::UID
          def satisfies?(parc, _)
            parc.resource == ref
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("resource = ")
            q.pp(ref)
          end
        end

        class In < Literal::Struct
          include Resource
          prop :ref, Entity::UID
          def satisfies?(parc, entities)
            entities.in?(lhs: parc.resource, rhs: ref)
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("resource in ")
            q.pp(ref)
          end
        end

        class Is < Literal::Struct
          include Resource
          prop :type, String
          prop :ref, _Nilable(Entity::UID)

          def satisfies?(parc, entities)
            return false unless entities.is?(lhs: parc.resource, type:)

            ref ? entities.in?(lhs: parc.resource, rhs: ref) : true
          end

          def pretty_print(q) # rubocop:disable Naming/MethodParameterName
            q.text("resource is ")
            q.text(type)
            return unless ref

            q.text(" in ")
            q.pp(ref)
          end
        end

        def self.from_json(json)
          case json.fetch("op")
          when "All"
            ALL
          else
            Resource[json.fetch("op")]
          end
        end
      end

      module Condition
        class When < Literal::Struct
          include Condition
          prop :expr, JsonExpr

          def satisfies(...)
            result = expr.evaluate(...)
            if result.is_a?(TrueClass)
              true
            elsif result.is_a?(FalseClass)
              false
            else
              raise Error, "Expected boolean, got #{result.inspect}"
            end
          rescue Error, Literal::TypeError, IPAddr::InvalidAddressError, RangeError => e
            e
          end
        end

        class Unless < Literal::Struct
          include Condition
          prop :expr, JsonExpr

          def satisfies(...)
            result = expr.evaluate(...)
            if result.is_a?(FalseClass)
              true
            elsif result.is_a?(TrueClass)
              false
            else
              raise Error, "Expected boolean, got #{result.inspect}"
            end
          rescue Error, Literal::TypeError => e
            e
          end
        end

        def self.included(_base)
          raise Error, "Use When or Unless"
        end

        def self.from_json(json)
          case json.fetch("kind")
          when "when"
            When
          when "unless"
            Unless
          else
            raise Error, "Unknown condition kind"
          end
        end

        def pretty_print(q) # rubocop:disable Naming/MethodParameterName
          q.text(self.class.name.downcase.split("::").last)
          q.group(0, "{", "}") do
            q.pp(expr)
          end
        end
      end

      prop :effect, Effect
      prop :principal, Principal
      prop :action, Action
      prop :resource, Resource
      prop :conditions, _Array(Condition)
      prop :annotations, _JSONData?

      def satisfies(...)
        principal = @principal.satisfies?(...)
        action = @action.satisfies?(...)
        resource = @resource.satisfies?(...)

        pp(principal:, action:, resource:) if false # rubocop:disable Lint/LiteralAsCondition

        return false unless principal && action && resource

        conditions.each do |cond|
          res = cond.satisfies(...)
          return res unless res == true
        end

        true
      end

      def self.from_json(json)
        new(
          effect: Effect[json["effect"]],
          principal: Principal.from_json(json["principal"]),
          action: Action.from_json(json["action"]),
          resource: Resource.from_json(json["resource"]),
          conditions: json["conditions"]&.map { Condition.new(_1) }
        )
      end

      def pretty_print(q) # rubocop:disable Naming/MethodParameterName
        annotations.each do |annotation|
          annotation.each do |k, v|
            q.text("@#{k}(")
            q.pp(v)
            q.text(")\n")
          end
        end
        q.text(effect.value)
        q.group(2, " (", ")") do
          q.breakable
          q.pp(principal)
          q.text(",")
          q.breakable
          q.pp(action)
          q.text(",")
          q.breakable
          q.pp(resource)
          q.breakable
        end
        conditions.each do |cond|
          q.pp(cond)
          q.breakable
        end
        q.text(";")
      end
    end

    class PolicySet < Literal::Struct
      class Reference < Literal::Struct
        prop :condition, String
        prop :name, String
      end

      prop :static_policies, _Array(Policy)
      prop :templates, _Array(Policy)
      prop :template_links,
           _Array(_Map(**{ "templateId" => String, "newId" => String, "values" => _Hash(String, String) }))

      def self.from_json(json)
        new(
          static_policies: json["staticPolicies"]&.map { Policy.from_json(_1) },
          templates: json["templates"] || [],
          template_links: json["templateLinks"] || []
        )
      end

      def self.parse(string)
        PolicyParser.parse(string)
      end
    end

    class PolicyParser
      class Error < Error
      end

      def self.parse(string)
        new(string).parse
      end

      if false # rubocop:disable Lint/LiteralAsCondition
        def self.method_added(name)
          super
          return unless name.match?(/\Aparse_/) && !method_defined?(:"__#{name}") # rubocop:disable Performance/StartWith

          alias_method :"__#{name}", name
          define_method(name) do |*args|
            pos = @scanner.pos
            send(:"__#{name}", *args).tap do |result|
              pp(name => result, args:, span: @scanner.string[pos...@scanner.pos]) if result || @scanner.pos != pos
            end
          end
        end
      end

      def initialize(string)
        require "strscan"
        @scanner = StringScanner.new(string)
      end

      def parse
        policies = []
        loop do
          skip_trivia
          break if @scanner.eos?

          policies << parse_policy
        end
        PolicySet.new(static_policies: policies, templates: [], template_links: [])
      rescue StandardError => e
        context = @scanner.string[0..@scanner.pos]
        raise e.exception("Error parsing policy: #{e.message}\n#{context.inspect}\n\n" \
                          "#{@scanner.string[@scanner.pos..].inspect}")
      end

      def parse_policy
        annotations = []
        loop do
          skip_trivia
          a = parse_annotation
          break unless a

          annotations << a
        end

        effect = parse_effect || raise(Error, "Expected effect")
        skip_trivia
        @scanner.skip("(") || raise(Error, "Expected (")
        principal, action, resource = parse_scope
        skip_trivia
        @scanner.skip(")") || raise(Error, "Expected )")
        conditions = []
        # TODO: ensure that parse_condition made progress
        loop do
          skip_trivia
          break if @scanner.skip(";")

          conditions << parse_condition
        end

        skip_trivia

        Policy.new(effect:, principal:, action:, resource:, conditions:,
                   annotations:)
      end

      def skip_trivia
        @scanner.skip(%r{(?:\s+|//.*|\n)+})
      end

      def parse_effect
        Policy::Effect.fetch(@scanner.scan(/permit|forbid/))
      end

      def parse_scope
        principal = parse_principal
        @scanner.skip(",") || raise(Error, "Expected ,")
        action = parse_action
        @scanner.skip(",") || raise(Error, "Expected ,")
        resource = parse_resource
        [principal, action, resource]
      end

      def parse_principal
        skip_trivia
        raise Error, "missing principal" unless @scanner.skip("principal")

        skip_trivia
        case @scanner.scan(/is|in|==/)
        when nil
          Policy::Principal::ALL
        when "=="
          ref = parse_entity || parse_literal("?principal")
          Policy::Principal::Eq.new(ref:)
        when "in"
          ref = parse_entity || parse_literal("?principal")
          Policy::Principal::In.new(ref:)
        when "is"
          skip_trivia
          path = parse_path || raise(Error, "Expected path")
          skip_trivia
          ref = parse_entity || parse_literal("?principal") if @scanner.skip("in")
          Policy::Principal::Is.new(type: path, ref:)
        else
          raise Error, "Expected is, in, or =="
        end
      end

      def parse_action
        skip_trivia
        @scanner.skip("action")
        skip_trivia
        case @scanner.scan(/is|in|==/)
        when nil
          Policy::Action::ALL
        when "=="
          Policy::Action::Eq.new(ref: parse_entity || parse_literal("?action"))
        when "in"

          l = surrounded("[", "]") { parse_ent_list } || parse_entity || parse_literal("?action")
          Policy::Action::In.new(refs: l)
        else
          raise Error, "Expected is, in, or =="
        end
      end

      def parse_resource
        skip_trivia
        @scanner.skip("resource")
        skip_trivia
        case (op = @scanner.scan(/is|in|==/)&.tap { skip_trivia })
        when nil
          Policy::Resource::ALL
        when "in"
          Policy::Resource::In.new(ref: parse_entity || parse_literal("?resource"))
        when "=="
          Policy::Resource::Eq.new(ref: parse_entity || parse_literal("?resource"))
        when "is"
          skip_trivia
          path = parse_path || raise(Error, "Expected path")
          skip_trivia
          ref = parse_entity || parse_literal("?resource") if @scanner.skip("in")
          Policy::Resource::Is.new(type: path, ref:)
        else
          raise Error, "Handle #{op.inspect}"
        end
      end

      def parse_annotation
        return unless @scanner.skip(/@/)

        ident = parse_any_ident || raise(Error, "Expected identifier")
        @scanner.skip("(") || raise(Error, "Expected (")
        string = parse_str
        @scanner.skip(")") || raise(Error, "Expected )")
        { ident => string }
      end

      def parse_any_ident
        @scanner.scan(/[a-zA-Z_][a-zA-Z0-9_]*/)
      end

      def parse_str
        return unless (str = @scanner.scan(/"(?:[^"\\]|\\.)*"/))

        str.gsub!(/(?<!\\)((?:\\\\)+)?\\0/, '\1\u0000')
        str.gsub!(/(?<!\\)((?:\\\\)+)?\\'/, "\\1'")
        replace = ->(c) { "\\u#{c.ord.to_s(16).rjust(4, "0")}" }
        str.encode!(Encoding::US_ASCII, fallback: replace)

        str.undump.encode(Encoding::UTF_8)
      rescue RuntimeError => e
        raise e.exception("Error parsing string: #{e.message}\n\t#{str}")
      end

      def parse_literal(literal)
        @scanner.skip(literal) || raise(Error, "Expected #{literal.inspect}")
      end

      def parse_entity
        skip_trivia
        pos = @scanner.pos
        return unless (path = parse_path)

        unless @scanner.skip("::")
          @scanner.pos = pos
          return
        end
        id = parse_str || raise(Error, "Expected string")
        Entity::UID.new(type: path, id:)
      end

      def parse_path
        return unless (ident = parse_ident)

        path = [ident]
        loop do
          pos = @scanner.pos
          (@scanner.skip(/::/) && (id = parse_ident)) || (break @scanner.pos = pos)
          path << id
        end
        path.join("::")
      end

      def parse_ident
        case ident = parse_any_ident
        when "true", "false", "if", "then", "else", "in", "like", "has", "is", "__cedar"
          @scanner.unscan
          nil
        else
          ident
        end
      end

      def parse_condition
        kind = @scanner.scan(/when|unless/) || raise(Error, "Expected when or unless")
        skip_trivia
        parse_literal("{")
        skip_trivia

        expr = parse_expr
        parse_literal("}")
        case kind
        when "when"
          Policy::Condition::When.new(expr:)
        when "unless"
          Policy::Condition::Unless.new(expr:)
        end
      end

      def parse_expr
        skip_trivia
        if (o = parse_or)
          return o
        end

        return unless @scanner.skip("if")

        c = parse_expr
        parse_literal("then")
        t = parse_expr
        parse_literal("else")
        e = parse_expr
        Policy::JsonExpr::IfThenElse.new(cond: c, then: t, else: e)
      end

      def parse_or
        return unless (a = parse_and)

        o = a
        loop do
          skip_trivia
          break unless @scanner.skip("||")

          o = Policy::JsonExpr::BinaryOp.new(op: Policy::JsonExpr::BinaryOp::Op::Or, lhs: o, rhs: parse_and)
        end
        o
      end

      def parse_and
        return unless (r = parse_relation)

        a = r
        loop do
          skip_trivia
          break unless @scanner.skip("&&")

          rhs = parse_relation
          raise Error, "Expected relation" unless rhs

          a = Policy::JsonExpr::BinaryOp.new(op: Policy::JsonExpr::BinaryOp::Op::And, lhs: a, rhs:)
        end
        a
      end

      def parse_relation
        return unless (add = parse_add)
        return add unless (op = @scanner.scan(Regexp.union("<=", "<", ">=", ">", "!=", "==", "in", "has", "like",
                                                           "is")))

        skip_trivia

        case op
        when "has"
          Policy::JsonExpr::Has.new(left: add, attr: parse_ident || parse_str)
        when "like"
          Policy::JsonExpr::BinaryOp.new(op: Policy::JsonExpr::BinaryOp::Op.fetch(op), lhs: add, rhs: parse_pat)
        when "is"
          path = parse_path
          i = parse_add if @scanner.skip("in")
          Policy::JsonExpr::Is.new(left: add, entity_type: path, in: i)
        else
          Policy::JsonExpr::BinaryOp.new(op: Policy::JsonExpr::BinaryOp::Op.fetch(op), lhs: add, rhs: parse_add)
        end
      end

      def parse_add
        return unless (lhs = parse_mult)

        a = lhs
        loop do
          op = @scanner.scan(/[-+]/) || break
          a = Policy::JsonExpr::BinaryOp.new(op: Policy::JsonExpr::BinaryOp::Op[op], lhs: a, rhs: parse_mult)
        end
        a
      end

      def parse_mult
        skip_trivia
        return unless (unary = parse_unary)

        mult = unary
        loop do
          break unless @scanner.skip("*")

          mult = Policy::JsonExpr::BinaryOp.new(op: Policy::JsonExpr::BinaryOp::Op::Mul, lhs: mult, rhs: parse_unary)
        end
        mult
      end

      def parse_unary
        prefix = @scanner.scan(/[!-]{1,4}/)
        member = parse_member

        case prefix
        when nil
          member
        when "!"
          Policy::JsonExpr::Not.new(expr: member)
        when "-"
          Policy::JsonExpr::Neg.new(expr: member)
        else
          raise Error, "Unary operator #{prefix.inspect} not implemented for #{member}"
        end
      end

      def parse_member
        return unless (primary = parse_primary)

        member = primary
        loop do
          a = parse_access
          case a
          when nil
            break
          when Policy::JsonExpr::Function
            Literal.check(actual: member, expected: Policy::JsonExpr)
            a.args.unshift(member)
            member = a
          else
            member = Policy::JsonExpr::Dot.new(left: member, attr: a)
          end
        end
        member
      end

      def parse_primary
        skip_trivia
        parse_lit ||
          parse_var || parse_entity || begin
            pos = @scanner.pos
            ef = parse_extfun
            if ef && (e = surrounded("(", ")") { parse_expr_list || [] })
              Policy::JsonExpr::Function.new(name: ef, args: e)
            else
              @scanner.pos = pos
              nil
            end
          end ||
          surrounded("(", ")") { parse_expr } ||
          surrounded("[", "]") { parse_expr_list || [] }&.then { Policy::JsonExpr::Value.new(value: _1) } ||
          surrounded("{", "}") { parse_rec_inits || Policy::JsonExpr::Value.new(value: {}) }
      end

      def surrounded(left, right)
        pos = @scanner.pos
        skip_trivia
        return unless @scanner.skip(left)

        skip_trivia

        unless (ret = yield)
          @scanner.pos = pos
          return
        end

        skip_trivia
        unless @scanner.skip(right)
          @scanner.pos = pos
          return
        end
        ret
      end

      def parse_lit
        if @scanner.skip("true")
          true
        elsif @scanner.skip("false")
          false
        elsif (match = @scanner.scan(/-?[0-9]+/))
          match.to_i
        elsif (match = parse_str)
          match
        end&.then do |value|
          Policy::JsonExpr::Value.new(value:)
        end
      end

      def parse_access
        skip_trivia
        if @scanner.skip(".")
          ident = parse_ident || raise(Error, "no ident")
          if (l = surrounded("(", ")") { parse_expr_list || [] })
            Policy::JsonExpr::Function.new(name: ident, args: l)
          else
            ident
          end
        else
          surrounded("[", "]") { parse_str }
        end
      end

      def parse_var
        Policy::JsonExpr::Var[@scanner.scan(/principal|action|resource|context/)]
      end

      def parse_expr_list
        return unless (e = parse_expr)

        list = [e]
        loop do
          break unless @scanner.skip(",")

          list << parse_expr
        end
        list
      end

      def parse_extfun
        pos = @scanner.pos
        if (path = parse_path)
          unless @scanner.skip("::")
            @scanner.pos = pos
            return parse_ident
          end
          [path, parse_ident]
        else
          parse_ident
        end
      end

      def parse_ent_list
        list = []
        return list unless (ent = parse_entity)

        list << ent
        loop do
          break unless @scanner.skip(",")

          list << parse_entity
        end
        list
      end

      def parse_rec_inits
        record = {}

        skip_trivia
        k = parse_ident || parse_str
        return unless k

        @scanner.skip(":") || raise(Error, "Expected :")
        skip_trivia
        v = parse_expr

        record[k] = v

        loop do
          break unless @scanner.skip(",")

          skip_trivia

          k = parse_ident || parse_str
          @scanner.skip(":") || raise(Error, "Expected :")
          skip_trivia
          v = parse_expr

          record[k] = v
        end

        Policy::JsonExpr::Value.new(value: record)
      end

      def parse_pat
        parse_str&.then do |str|
          Policy::JsonExpr::Value.new(value: str)
        end
      end
    end

    class Schema
      def self.parse(string)
        SchemaParser.parse(string)
      end
    end

    class SchemaParser
      def self.parse(string)
        new(string).parse
      end

      def initialize(string)
        @scanner = StringScanner.new(string)
      end

      def parse
        []
      end
    end
  end
end
