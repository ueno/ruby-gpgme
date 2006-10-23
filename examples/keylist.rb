#!/usr/bin/env ruby
require 'gpgme'

GPGME.each_key(ARGV.shift) do |key|
  puts(key)
end
