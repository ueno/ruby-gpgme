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
}
ctx.set_passphrase_cb(passphrase_cb)

progress_cb = proc {|hook, what, type, current, total|
  $stderr.write("#{what}: #{current}/#{total}\r")
  $stderr.flush
}

#ctx.set_progress_cb(progress_cb)
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
