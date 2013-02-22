require 'mkmf'

BUILD   = Dir::pwd
SRC     = File.expand_path(File.dirname(__FILE__))
PREFIX  = "#{BUILD}/dst"

def sys(*cmd)
  puts "  -- #{cmd.join(' ')}"

  unless ret = xsystem(cmd.join(' '))
    raise "#{cmd.join(' ')} failed!"
  end

  ret
end

def build(tgz, *flags)
  sys("tar xjvf #{tgz}")

  Dir.chdir(File.basename(tgz, '.tar.bz2')) do
    sys("./configure --prefix=#{PREFIX} --libdir=#{PREFIX}/lib --disable-shared --enable-static --with-pic", *flags)
    sys("make")
    sys("make install")
  end
end

libgpg_error_tgz  = File.join(SRC, 'libgpg-error-1.10.tar.bz2')
libassuan_tgz     = File.join(SRC, 'libassuan-2.0.2.tar.bz2')
gpgme_tgz         = File.join(SRC, 'gpgme-1.3.1.tar.bz2')

# build deps

build(libgpg_error_tgz, "--disable-nls")
build(libassuan_tgz, "--with-gpg-error-prefix=#{PREFIX}")
build(gpgme_tgz, "--with-gpg-error-prefix=#{PREFIX}", "--with-libassuan-prefix=#{PREFIX}")

# copy gpgme


%w[ libassuan libgpg-error libgpgme ].each do |lib|
  FileUtils.cp "#{PREFIX}/lib/#{lib}.a", "#{BUILD}/#{lib}_ext.a"
end

$INCFLAGS[0,0] = " -I#{PREFIX}/include "
#$LDFLAGS << " -L#{PREFIX}/lib "
$CFLAGS << " -fPIC "

# build gpgme extension

unless have_library 'gpg-error_ext' and have_library 'assuan_ext' and have_library 'gpgme_ext' and have_header 'gpgme.h'
  STDERR.puts "\n\n"
  STDERR.puts "*********************************************************"
  STDERR.puts "********* error compiling and linking libgpgme. *********"
  STDERR.puts "*********************************************************"
  exit(1)
end

create_makefile ('gpgme_n')
