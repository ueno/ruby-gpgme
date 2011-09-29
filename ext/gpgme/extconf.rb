require 'mkmf'

CWD     = File.expand_path(File.dirname(__FILE__))
PREFIX  = "#{CWD}/dst/"

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
    sys("./configure --prefix=#{PREFIX} --disable-shared --enable-static --with-pic", *flags)
    sys("make")
    sys("make install")
  end
end

libgpg_error_tgz  = File.join(CWD, 'libgpg-error-1.10.tar.bz2')
libassuan_tgz     = File.join(CWD, 'libassuan-2.0.2.tar.bz2')
gpgme_tgz         = File.join(CWD, 'gpgme-1.3.1.tar.bz2')

# build deps

build(libgpg_error_tgz, "--disable-nls")
build(libassuan_tgz, "--with-gpg-error-prefix=#{PREFIX}")
build(gpgme_tgz, "--with-gpg-error-prefix=#{PREFIX}", "--with-libassuan-prefix=#{PREFIX}")

# copy gpgme


%w[ libassuan libgpg-error libgpgme ].each do |lib|
  FileUtils.cp "#{CWD}/dst/lib/#{lib}.a", "#{CWD}/#{lib}_ext.a"
end

$INCFLAGS[0,0] = " -I#{CWD}/dst/include "
#$LDFLAGS << " -L#{CWD} "
$CFLAGS << " -fPIC "

# build gpgme extension

unless have_library 'gpg-error_ext' and have_library 'gpgme_ext' and have_library 'assuan_ext' and have_library 'gpg-error_ext' and have_header 'gpgme.h'
  STDERR.puts "\n\n"
  STDERR.puts "*********************************************************"
  STDERR.puts "********* error compiling and linking libgpgme. *********"
  STDERR.puts "*********************************************************"
  exit(1)
end

create_makefile ('gpgme_n')
