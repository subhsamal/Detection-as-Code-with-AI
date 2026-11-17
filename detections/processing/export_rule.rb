# Local YAML-to-JSON conversion only. No network or deployment operations.
require 'yaml'
require 'json'

abort 'Usage: ruby detections/processing/export_rule.rb RULE.yml' unless ARGV.length == 1
rule = YAML.safe_load(File.read(ARGV.fetch(0)), permitted_classes: [], permitted_symbols: [], aliases: false)
abort 'Expected disabled rule object' unless rule.is_a?(Hash) && rule['enabled'] == false
puts JSON.pretty_generate(rule)
