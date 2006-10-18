#!/usr/bin/env ruby
require 'gpgme'

GPGME::sign('test test test', $stdout, {:mode => GPGME::SIG_MODE_CLEAR})
