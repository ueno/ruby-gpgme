Gem::Specification.new do |s|
  s.name              = 'gpgme'
  s.version           = '2.0.20'
  s.authors           = ['Daiki Ueno', 'Albert Llop']
  s.date              = '2018-11-22'
  s.email             = 'ueno@gnu.org'
  s.extensions        = ['ext/gpgme/extconf.rb']
  s.files             = Dir['{lib,ext,test,examples}/**/*'] +
                        Dir['ports/archives/*']
  s.rubyforge_project = 'ruby-gpgme'
  s.homepage          = 'http://github.com/ueno/ruby-gpgme'
  s.license           = 'LGPL-2.1+'
  s.require_paths     = ['lib', 'ext']
  s.summary           = 'Ruby binding of GPGME.'
  s.description       = %q{Ruby-GPGME is a Ruby language binding of GPGME (GnuPG
Made Easy). GnuPG Made Easy (GPGME) is a library designed to make access to
GnuPG easier for applications. It provides a High-Level Crypto API for
encryption, decryption, signing, signature verification and key management.}

  s.add_runtime_dependency "mini_portile2", "~>2.7.0"

  s.add_development_dependency "mocha",     "~> 0.9.12"
  s.add_development_dependency "minitest",  "~> 2.1.0"
  s.add_development_dependency "yard",      "~> 0.9.11"
  s.add_development_dependency "coveralls"
  s.add_development_dependency "byebug"
end
