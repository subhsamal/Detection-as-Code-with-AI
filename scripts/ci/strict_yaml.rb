# Strict, data-only YAML policy. No object construction, tags, aliases or merges.
# Mapping keys remain strings (including GitHub Actions' YAML 1.2 `on` key).
require 'yaml'
require 'json'

def convert(node)
  case node
  when Psych::Nodes::Mapping
    raise 'Explicit tags are forbidden' if node.tag
    result = {}
    node.children.each_slice(2) do |key, value|
      raise 'Only scalar mapping keys are allowed' unless key.is_a?(Psych::Nodes::Scalar)
      raise 'Tags and merge keys are forbidden' if key.tag || key.value == '<<'
      raise "Duplicate mapping key at line #{key.start_line + 1}" if result.key?(key.value)
      result[key.value] = convert(value)
    end
    result
  when Psych::Nodes::Sequence
    raise 'Explicit tags are forbidden' if node.tag
    node.children.map { |child| convert(child) }
  when Psych::Nodes::Scalar
    raise 'Explicit tags are forbidden' if node.tag
    return node.value unless node.style == Psych::Nodes::Scalar::PLAIN
    value = node.value
    case value
    when /\A(?:null|~)?\z/i then nil
    when /\Atrue\z/i then true
    when /\Afalse\z/i then false
    when /\A[-+]?(?:0|[1-9][0-9]*)\z/ then Integer(value, 10)
    when /\A[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?\z/,
         /\A[-+]?[0-9]+[eE][-+]?[0-9]+\z/
      number = Float(value)
      raise 'Non-finite numbers are forbidden' unless number.finite?
      number
    when /\A[-+]?\.(?:inf|nan)\z/i then raise 'Non-finite numbers are forbidden'
    else value
    end
  else
    raise 'Aliases and unsupported YAML nodes are forbidden'
  end
end

begin
  args = ARGV.dup
  json_output = args.delete('--json')
  raise 'Exactly one YAML path required' unless args.length == 1
  stream = Psych.parse_stream(File.read(args[0]))
  raise 'Exactly one YAML document required' unless stream.children.length == 1
  value = convert(stream.children.first.root)
  puts(json_output ? JSON.generate(value) : 'PASS | Strict YAML')
rescue StandardError
  warn 'FAIL | Strict YAML policy or syntax; document content suppressed'
  exit 1
end
