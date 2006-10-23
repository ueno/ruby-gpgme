require 'mkmf'

unless find_executable('gpgme-config')
  $stderr.puts("gpgme-config not found")
  exit(1)
end

$CFLAGS += ' ' << `gpgme-config --cflags`.chomp
$libs += ' ' << `gpgme-config --libs`.chomp

create_makefile ('gpgme_n')
