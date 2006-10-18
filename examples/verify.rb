#!/usr/bin/env ruby
require 'gpgme'

GPGME::verify(ARGF.read, nil, $stdout) do |signature|
  puts(signature.to_s)
end
