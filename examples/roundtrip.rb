#!/usr/bin/env ruby
require 'gpgme'

ctx = GPGME::Ctx.new({:armor => true})
passphrase_cb = proc {|hook, uid_hint, passphrase_info, prev_was_bad, fd|
  io = IO.for_fd(fd, 'w')
  io.puts('test')
  io.flush
  GPGME::GPG_ERR_NO_ERROR
}
ctx.set_passphrase_cb(passphrase_cb)

plain = GPGME::Data.new_from_mem('test test test')
puts("Plaintext:\n#{plain.read}")
plain.rewind

# Perform symmetric encryption on PLAIN.
cipher = ctx.encrypt(nil, plain)
cipher.rewind
puts("Ciphertext:\n#{cipher.read}")
cipher.rewind

plain = ctx.decrypt(cipher)
plain.rewind
puts("Plaintext:\n#{plain.read}")
