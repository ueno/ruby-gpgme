Gem::Specification.new do |s|
  s.name = 'ruby-gpgme'
  s.version = '1.0.9'
  s.authors = ['Daiki Ueno']
  s.date = '2010-05-21'
  s.email = 'ueno@unixuser.org'
  s.extensions = ['extconf.rb']
  s.files = ['COPYING', 'COPYING.LESSER', 'Makefile', 'README',
             'THANKS', 'extconf.rb', 'gpgme_n.c', 'lib/gpgme.rb',
             'lib/gpgme/compat.rb', 'lib/gpgme/constants.rb',
             'examples/sign.rb', 'examples/genkey.rb', 'examples/keylist.rb',
             'examples/verify.rb', 'examples/roundtrip.rb', 'examples/edit.rb']
  s.has_rdoc = true
  s.rubyforge_project = 'ruby-gpgme'
  s.homepage = 'http://rubyforge.org/projects/ruby-gpgme/'
  s.require_paths = ['lib']
  s.summary = 'Ruby binding of GPGME.'
end
