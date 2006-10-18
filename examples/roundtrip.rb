#!/usr/bin/env ruby
require 'gpgme'

plain = 'test test test'
puts("Plaintext:\n#{plain}")

# Perform symmetric encryption on PLAIN.
cipher = GPGME::encrypt(nil, plain, {:armor => true})
puts("Ciphertext:\n#{cipher}")

plain = GPGME::decrypt(cipher)
puts("Plaintext:\n#{plain}")
