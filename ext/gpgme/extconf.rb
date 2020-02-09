require 'mkmf'

# Available options:
#
# --enable-clean (default)
# --disable-clean
#
# This file is largely based on Nokogiri's extconf.rb.

ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..'))

if arg_config('--clean')
  require 'pathname'
  require 'fileutils'

  root = Pathname(ROOT)
  pwd  = Pathname(Dir.pwd)

  # Skip if this is a development work tree
  unless (root + '.git').exist?
    message "Cleaning files only used during build.\n"

    # (root + 'tmp') cannot be removed at this stage because
    # gpgme_n.so is yet to be copied to lib.

    # clean the ports build directory
    Pathname.glob(pwd.join('tmp', '*', 'ports')) { |dir|
      FileUtils.rm_rf(dir, { :verbose => true })
      FileUtils.rmdir(dir.parent, { :parents => true, :verbose => true })
    }

    # ports installation can be safely removed if statically linked.
    FileUtils.rm_rf(root + 'ports', { :verbose => true })
  end

  exit
end

if arg_config('--use-system-libraries', ENV['RUBY_GPGME_USE_SYSTEM_LIBRARIES'])
  unless find_executable('gpgme-config')
    $stderr.puts("gpgme-config not found")
    exit(1)
  end

  $CFLAGS += ' ' << `gpgme-config --cflags`.chomp
  $libs += ' ' << `gpgme-config --libs`.chomp
else
  message <<-'EOS'
************************************************************************
IMPORTANT!  gpgme gem uses locally built versions of required C libraries,
namely libgpg-error, libassuan, and gpgme.

If this is a concern for you and you want to use the system library
instead, abort this installation process and reinstall gpgme gem as
follows:

    gem install gpgme -- --use-system-libraries

************************************************************************
EOS

  require 'rubygems'
  require 'mini_portile2'

  libgpg_error_recipe = MiniPortile.new('libgpg-error', '1.37').tap do |recipe|
    recipe.target = File.join(ROOT, "ports")
    recipe.files = [{
      :url => "https://www.gnupg.org/ftp/gcrypt/#{recipe.name}/#{recipe.name}-#{recipe.version}.tar.bz2",
      :sha256 => 'b32d6ff72a73cf79797f7f2d039e95e9c6f92f0c1450215410840ab62aea9763'
    }]
    recipe.configure_options = [
      '--disable-shared',
      '--enable-static',
      '--disable-nls',
      "CFLAGS=-fPIC #{ENV["CFLAGS"]}",
    ]
    checkpoint = "#{recipe.target}/#{recipe.name}-#{recipe.version}-#{recipe.host}.installed"
    unless File.exist?(checkpoint)
      recipe.cook
      FileUtils.touch checkpoint
    end
    recipe.activate
  end

  libassuan_recipe = MiniPortile.new('libassuan', '2.5.3').tap do |recipe|
    recipe.target = File.join(ROOT, "ports")
    recipe.files = [{
      :url => "https://www.gnupg.org/ftp/gcrypt/#{recipe.name}/#{recipe.name}-#{recipe.version}.tar.bz2",
      :sha256 => '91bcb0403866b4e7c4bc1cc52ed4c364a9b5414b3994f718c70303f7f765e702'
    }]
    recipe.configure_options = [
      '--disable-shared',
      '--enable-static',
      "--with-gpg-error-prefix=#{libgpg_error_recipe.path}",
      "CFLAGS=-fPIC #{ENV["CFLAGS"]}",
    ]
    checkpoint = "#{recipe.target}/#{recipe.name}-#{recipe.version}-#{recipe.host}.installed"
    unless File.exist?(checkpoint)
      recipe.cook
      FileUtils.touch checkpoint
    end
    recipe.activate
  end

  gpgme_recipe = MiniPortile.new('gpgme', '1.13.1').tap do |recipe|
    recipe.target = File.join(ROOT, "ports")
    recipe.files = [{
      :url => "https://www.gnupg.org/ftp/gcrypt/#{recipe.name}/#{recipe.name}-#{recipe.version}.tar.bz2",
      :sha256 => 'c4e30b227682374c23cddc7fdb9324a99694d907e79242a25a4deeedb393be46'
    }]
    recipe.configure_options = [
      '--disable-shared',
      '--enable-static',
      "--with-gpg-error-prefix=#{libgpg_error_recipe.path}",
      "--with-libassuan-prefix=#{libassuan_recipe.path}",
      # GPGME 1.5.0 assumes gpgsm is present if gpgconf is found.
      # However, on some systems (e.g. Debian), they are splitted into
      # separate packages.
      '--disable-gpgconf-test',
      '--disable-gpg-test',
      '--disable-gpgsm-test',
      '--disable-g13-test',
      # We only need the C API.
      '--disable-languages',
      "CFLAGS=-fPIC #{ENV["CFLAGS"]}",
    ]
    checkpoint = "#{recipe.target}/#{recipe.name}-#{recipe.version}-#{recipe.host}.installed"
    unless File.exist?(checkpoint)
      recipe.cook
      FileUtils.touch checkpoint
    end
    recipe.activate
  end

  # special treatment to link with static libraries
  $libs = $libs.shellsplit.tap {|libs|
    File.join(gpgme_recipe.path, "bin", "gpgme-config").tap {|config|
      # call config scripts explicit with 'sh' for compat with Windows
      $CPPFLAGS = `sh #{config} --cflags`.strip << ' ' << $CPPFLAGS
      `sh #{config} --libs`.strip.shellsplit.each {|arg|
        case arg
        when /\A-L(.+)\z/
          lpath=$1
          # Prioritize ports' directories
          if lpath.start_with?(ROOT + '/')
            $LIBPATH = [lpath] | $LIBPATH
          else
            $LIBPATH = $LIBPATH | [lpath]
          end
        when /\A-l(.+)\z/
          # Resolve absolute paths of local static libraries to avoid
          # linking with system libraries.
          libname_to_recipe = {
            'gpgme' => gpgme_recipe,
            'assuan' => libassuan_recipe,
            'gpg-error' => libgpg_error_recipe
          }
          recipe = libname_to_recipe[$1]
          if recipe
            libs.push(File.join(recipe.path, 'lib', "lib#{$1}.#{$LIBEXT}"))
          else
            libs.push(arg)
          end
        else
          $LDFLAGS << ' ' << arg.shellescape
        end
      }
    }
  }.shelljoin

  message 'checking for linker flags for static linking... '
  case
  when try_link('int main(void) { return 0; }',
                ['-Wl,-Bstatic', '-lgpgme', '-Wl,-Bdynamic'].shelljoin)
    message "-Wl,-Bstatic\n"

    $libs = $libs.shellsplit.map {|arg|
      case arg
      when '-lgpgme', '-lassuan', '-lgpg-error'
        ['-Wl,-Bstatic', arg, '-Wl,-Bdynamic']
      else
        arg
      end
    }.flatten.shelljoin
  else
    message "NONE\n"
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

if enable_config('clean', true)
  # Do not clean if run in a development work tree.
  File.open('Makefile', 'a') { |mk|
    mk.print <<EOF
all: clean-ports

clean-ports: $(DLLIB)
	-$(Q)$(RUBY) $(srcdir)/extconf.rb --clean
EOF
  }
end
