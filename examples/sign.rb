#!/usr/bin/env ruby
require 'gpgme'

puts(GPGME::sign('test test test', {:mode => GPGME::GPGME_SIG_MODE_CLEAR}))
