#!/usr/bin/env ruby
require 'gpgme'

ctx = GPGME::Ctx.new

passphrase_cb = proc {|hook, uid_hint, passphrase_info, prev_was_bad, fd|
  $stderr.write("Passphrase for #{uid_hint}: ")
  $stderr.flush
  begin
    system('stty -echo')
    io = IO.for_fd(fd, 'w')
    io.puts(gets.chomp)
    io.flush
  ensure
    system('stty echo')
  end
  puts
  GPGME::GPG_ERR_NO_ERROR
}
ctx.set_passphrase_cb(passphrase_cb)

plain = GPGME::Data.new_from_mem('test test test')

signed = ctx.sign(plain, GPGME::GPGME_SIG_MODE_CLEAR)
signed.rewind
puts("#{signed.read}")
