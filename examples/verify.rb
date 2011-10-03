#!/usr/bin/env ruby
require 'gpgme'

crypto = GPGME::Crypto.new
signature = GPGME::Data.new(ARGF.read)
crypto.verify(signature) do |sig|
  puts(sig.to_s)
end
