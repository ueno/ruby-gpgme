#!/usr/bin/env ruby
require 'gpgme'

ctx = GPGME::Ctx.new
ctx.each_key(ARGV.shift) do |key|
  puts(key)
end
