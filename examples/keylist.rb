#!/usr/bin/env ruby
require 'gpgme'

pat = ARGV.shift
ctx = GPGME::Ctx.new
ctx.each_keys(pat) do |key|
  puts(key.subkeys[0].keyid)
  key.uids.each do |user_id|
    puts("\t#{user_id.name} <#{user_id.email}>")
  end
end
