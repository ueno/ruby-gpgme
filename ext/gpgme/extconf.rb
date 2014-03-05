require 'mkmf'

BUILD = Dir::pwd
SRC = File.expand_path(File.dirname(__FILE__))
PREFIX = "#{BUILD}/dst"

def sys(*cmd)
  puts "  -- #{cmd.join(' ')}"

  unless ret = xsystem(cmd.join(' '))
    raise "#{cmd.join(' ')} failed!"
  end

  ret
end

def build(name, tgz, *flags)
  message <<-"EOS"
************************************************************************
IMPORTANT!  gpgme builds and uses a packaged version of #{name}.

If this is a concern for you and you want to use the system library
instead, abort this installation process and reinstall nokogiri as
follows:

    gem install gpgme -- --use-system-libraries

************************************************************************
EOS

  sys("tar xjvf #{tgz}")

  Dir.chdir(File.basename(tgz, '.tar.bz2')) do
    sys("./configure --prefix=#{PREFIX} --libdir=#{PREFIX}/lib --disable-shared --enable-static --with-pic", *flags)
    sys("make")
    sys("make install")
  end
end

if arg_config('--use-system-libraries', ENV['RUBY_GPGME_USE_SYSTEM_LIBRARIES'])
  unless find_executable('gpgme-config')
    $stderr.puts("gpgme-config not found")
    exit(1)
  end

  $CFLAGS += ' ' << `gpgme-config --cflags`.chomp
  $libs += ' ' << `gpgme-config --libs`.chomp
else
  $INCFLAGS[0,0] = " -I#{PREFIX}/include "
  #$LDFLAGS << " -L#{PREFIX}/lib "
  $CFLAGS << " -fPIC "

  deps = {
    'libgpg-error' => {
      :lib => 'libgpg-error',
      :tarball => 'libgpg-error-1.12.tar.bz2',
      :configure_options => ['--disable-nls']
    },
    'libassuan' => {
      :lib => 'libassuan',
      :tarball => 'libassuan-2.1.1.tar.bz2',
      :configure_options => ["--with-gpg-error-prefix=#{PREFIX}"]
    },
    'gpgme' => {
      :lib => 'libgpgme',
      :tarball => 'gpgme-1.4.3.tar.bz2',
      :configure_options => ["--with-gpg-error-prefix=#{PREFIX}",
                             "--with-libassuan-prefix=#{PREFIX}"]
    }
  }

  # build libraries in the right order
  %w[libgpg-error libassuan gpgme].each do |name|
    options = deps[name]
    build(name, File.join(SRC, options[:tarball]), *options[:configure_options])
  end

  # rename locally built libraries so it will not conflict with system libraries
  deps.each do |name, options|
    File.rename("#{PREFIX}/lib/#{options[:lib]}.a",
                "#{BUILD}/#{options[:lib]}_ext.a")

    unless have_library "#{options[:lib][3..-1]}_ext"
      abort <<-"EOS"
************************************************************************
ERROR!  Cannot link to #{options[:lib]}.
************************************************************************
EOS
    end
  end

  unless have_header 'gpgme.h'
    abort <<-EOS
************************************************************************
ERROR!  Cannot locate 'gpgme.h'.
************************************************************************
EOS
  end
end

checking_for('gpgme >= 1.1.3') do
  if try_run(<<'End')
#include <gpgme.h>
#include <stdlib.h>
int main (void) {
  return gpgme_check_version ("1.1.3") == NULL;
}
End
    true
  else
    $CFLAGS += ' -DRUBY_GPGME_NEED_WORKAROUND_KEYLIST_NEXT'
    false
  end
end

have_func('gpgme_op_export_keys')

create_makefile ('gpgme_n')
