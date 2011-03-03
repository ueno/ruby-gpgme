# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "gpgme/version"

Gem::Specification.new do |s|
  s.name        = "gpgme"
  s.version     = GPGME::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Daiki Ueno"]
  s.email       = ["ueno@unixuser.org"]
  s.summary     = %q{Use the gpgme functionality from ruby}
  s.description = %q{Ruby-GPGME is a Ruby language binding of GPGME (GnuPG Made
Easy). GnuPG Made Easy (GPGME) is a library designed to make access to GnuPG
easier for applications. It provides a High-Level Crypto API for encryption,
decryption, signing, signature verification and key management.}

  s.add_development_dependency "mocha",     "~> 0.9.12"
  s.add_development_dependency "minitest",  "~> 2.1.0"
  s.add_development_dependency "yard",      "~> 0.6.7"
  s.add_development_dependency "ruby-debug19"

  s.files         = `git ls-files`.split("\n")
  s.extensions    = ["extconf.rb"]
  s.require_paths = ["lib"]
end
