#!/usr/bin/env ruby
require 'gpgme'

# If you do not have gpg-agent installed, comment out the following
# and set it as :passphrase_callback.
#
# def passfunc(hook, uid_hint, passphrase_info, prev_was_bad, fd)
#   $stderr.write("Passphrase for #{uid_hint}: ")
#   $stderr.flush
#   begin
#     system('stty -echo')
#     io = IO.for_fd(fd, 'w')
#     io.puts(gets)
#     io.flush
#   ensure
#     (0 ... $_.length).each do |i| $_[i] = ?0 end if $_
#     system('stty echo')
#   end
#   $stderr.puts
# end

unless ENV['GPG_AGENT_INFO']
  $stderr.puts("gpg-agent is not running.  See the comment in #{$0}.")
  exit(1)
end

plain = 'test test test'
puts("Plaintext:\n#{plain}")

# Perform symmetric encryption on PLAIN.
crypto = GPGME::Crypto.new(:armor => true)
cipher = crypto.encrypt(plain, {:symmetric => true,
			  # :passphrase_callback => method(:passfunc)
			})
str = cipher.read
puts("Ciphertext:\n#{str}")

cipher = GPGME::Data.new(str)
plain = crypto.decrypt(cipher, {
			 # :passphrase_callback => method(:passfunc)
		       })
puts("Plaintext:\n#{plain.read}")
