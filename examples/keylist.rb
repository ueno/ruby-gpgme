#!/usr/bin/env ruby
require 'gpgme'

GPGME.list_keys(ARGV.shift) do |key|
  puts(key)
end
