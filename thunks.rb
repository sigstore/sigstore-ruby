# frozen_string_literal: true

require "bundler/setup"
require "literal"
require "test/unit/autorunner"
require "kdl"

class Sentence < Literal::Struct
  prop :text, _String
end

class Document < Literal::Struct
  prop :title, _String
  prop :author, _String
  prop :paragraphs, _Array(Sentence)
end

class SentenceTransformer
  def self.transform(hash, _context)
    text = nil

    hash.each do |key, value|
      case key
      in "text"
        raise "Duplicate key: #{key}" if text
        raise "Bad type: #{value}" unless value.is_a?(String)

        text = value
      else
        raise "Unknown key: #{key}"
      end
    end

    Sentence.new(text: text)
  end
end

class SentenceKDLTransformer
  def self.transform(node, _context)
    raise "Single value expected" unless node.arguments.size == 1
    raise "No props expected" unless node.properties.empty?

    case node.name
    in "text"
      raise "Single value expected" unless node.arguments.size == 1
      raise "No props expected" unless node.properties.empty?
      unless (value = node.arguments.first).is_a?(KDL::Value::String)
        raise "Bad type: #{value}"
      end

      Sentence.new(text: value.value)
    end
  end
end

class DocumentTransformer
  def self.transform(hash, context)
    title = author = nil
    paragraphs = nil

    hash.each do |key, value|
      case key
      in "title"
        # only needed if source can have duplicate keys (e.g. KDL or XML, and not JSON)
        raise "Duplicate key: #{key}" if title
        raise "Bad type: #{value}" unless value.is_a?(String)

        title = value
      in "author"
        raise "Duplicate key: #{key}" if author
        raise "Bad type: #{value}" unless value.is_a?(String)

        author = value
      in "paragraphs" # NOTE: would work differently if the repeated values came in 1-by-1
        raise "Duplicate key: #{key}" if paragraphs
        raise "Bad type: #{value}" unless value.is_a?(Array)

        paragraphs = value.map do |v|
          raise "Bad type: #{v}" unless v.is_a?(Hash)

          SentenceTransformer.transform(v, context)
        end
      else
        raise "Unknown key: #{key}"
      end
    end

    Document.new(title: title, author: author, paragraphs: paragraphs)
  end
end

class DocumentKDLTransformer
  def self.transform(doc, context)
    title = author = nil
    paragraphs = []

    doc.nodes.each do |node|
      case node.name
      in "title"
        # only needed if source can have duplicate keys (e.g. KDL or XML, and not JSON)
        raise "Duplicate key: #{key}" if title
        raise "Single value expected" unless node.arguments.size == 1
        raise "No props expected" unless node.properties.empty?
        unless (value = node.arguments.first).is_a?(KDL::Value::String)
          raise "Bad type: #{value}"
        end

        title = value.value
      in "author"
        raise "Duplicate key: #{key}" if author
        raise "Single value expected" unless node.arguments.size == 1
        raise "No props expected" unless node.properties.empty?
        unless (value = node.arguments.first).is_a?(KDL::Value::String)
          raise "Bad type: #{value}"
        end

        author = value.value
      in "paragraph" # NOTE: would work differently if the repeated values came in 1-by-1
        raise "No arguments expected" unless node.arguments.empty?
        raise "No props expected" unless node.properties.empty?

        node.children.each do |child|
          paragraphs << SentenceKDLTransformer.transform(child, context)
        end
      else
        raise "Unknown key: #{key}"
      end
    end

    Document.new(title: title, author: author, paragraphs: paragraphs)
  end
end

class T < Test::Unit::TestCase
  def test1
    source = {
      "title" => "The Old",
      "author" => "John Doe",
      "paragraphs" => [
        { "text" => "Once upon a time" },
        { "text" => "There" }
      ]
    }

    DocumentTransformer.transform(source, nil) => Document[
      title: "The Old",
      author: "John Doe",
      paragraphs: [
        Sentence[text: "Once upon a time"],
        Sentence[text: "There"]
      ]
    ]
  end

  def test2
    source = KDL.parse_document <<~KDL
      title "The Old"
      author "John Doe"
      paragraph {
       text "Once upon a time"
      }
      paragraph {
       text "There"
      }
    KDL

    DocumentKDLTransformer.transform(source, nil) => Document[
      title: "The Old",
      author: "John Doe",
      paragraphs: [
        Sentence[text: "Once upon a time"],
        Sentence[text: "There"]
      ]
    ]
  end
end
