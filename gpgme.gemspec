Gem::Specification.new do |s|
  s.name              = 'gpgme'
  s.version           = '1.0.9'
  s.authors           = ['Daiki Ueno']
  s.date              = '2011-05-09'
  s.email             = 'ueno@unixuser.org'
  s.extensions        = ['ext/gpgme/extconf.rb']
  s.files             = `git ls-files`.split("\n")
  s.has_rdoc          = true
  s.rubyforge_project = 'ruby-gpgme'
  s.homepage          = 'http://rubyforge.org/projects/ruby-gpgme/'
  s.require_paths     = ['lib', 'ext']
  s.summary           = 'Ruby binding of GPGME.'
  s.description       = %q{Ruby-GPGME is a Ruby language binding of GPGME (GnuPG
Made Easy). GnuPG Made Easy (GPGME) is a library designed to make access to
GnuPG easier for applications. It provides a High-Level Crypto API for
encryption, decryption, signing, signature verification and key management.}

  s.add_development_dependency "mocha",     "~> 0.9.12"
  s.add_development_dependency "minitest",  "~> 2.1.0"
  s.add_development_dependency "yard",      "~> 0.6.7"
  s.add_development_dependency "rcov",      "~> 0.9.9"

  case RUBY_VERSION
  when "1.9.2"
    s.add_development_dependency "ruby-debug19" , "~> 0.11.6"
  else
    s.add_development_dependency "ruby-debug" , "~> 0.10.4"
  end
end
