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

unless ENV['GNUPGHOME']
  $stderr.write('As GNUPGHOME is not set, the generated key pair will be stored into *your* keyring.  Really proceed? (y/N) ')
  $stderr.flush
  exit(1) unless gets.chomp == 'y'
end
  
def progfunc(hook, what, type, current, total)
  $stderr.write("#{what}: #{current}/#{total}\r")
  $stderr.flush
end

ctx = GPGME::Ctx.new({:progress_callback => method(:progfunc),
		       # :passphrase_callback => method(:passfunc)
		     })

ctx.genkey(<<'EOF', nil, nil)
<GnupgKeyParms format="internal">
Key-Type: DSA
Key-Length: 1024
Subkey-Type: ELG-E
Subkey-Length: 1024
Name-Real: Joe Tester
Name-Comment: with stupid passphrase
Name-Email: joe@foo.bar
Expire-Date: 0
Passphrase: abc
</GnupgKeyParms>
EOF
$stderr.puts
