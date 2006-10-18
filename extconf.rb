require 'mkmf'

unless find_executable('gpgme-config')
  $stderr.puts("gpgme-config not found")
  exit(1)
end

if thread = with_config('thread')
  thread = "--thread=#{thread}"
end

$CFLAGS += ' ' << `gpgme-config #{thread} --cflags`.chomp
$libs += ' ' << `gpgme-config #{thread} --libs`.chomp

create_makefile ('gpgme_n')
