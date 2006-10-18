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
#   puts
# end

GPGME::sign('test test test', $stdout, {:mode => GPGME::SIG_MODE_CLEAR,
	      # :passphrase_callback => method(:passfunc)
	    })
