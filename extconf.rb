require 'mkmf'

unless find_executable('gpgme-config')
  $stderr.puts("gpgme-config not found")
  exit(1)
end

$CFLAGS += ' ' << `gpgme-config --cflags`.chomp
$libs += ' ' << `gpgme-config --libs`.chomp

unless try_run(<<'End')
#include <gpgme.h>
#include <stdlib.h>
int main (void) {
  return gpgme_check_version ("1.1.3") == NULL;
}
End
  $CFLAGS += ' -DRUBY_GPGME_NEED_WORKAROUND_KEYLIST_NEXT'
end
create_makefile ('gpgme_n')
