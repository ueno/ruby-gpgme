#!/usr/bin/env ruby
require 'gpgme'

plain = GPGME::verify(ARGF.read) do |signature|
  puts(signature.to_s)
end
puts(plain)
