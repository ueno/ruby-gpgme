require 'mkmf'

if have_library('gpgme', 'gpgme_check_version') and have_header('gpgme.h')
  create_makefile ('gpgme_n')
end
