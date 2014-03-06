require 'mkmf'

ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..'))

if arg_config('--use-system-libraries', ENV['RUBY_GPGME_USE_SYSTEM_LIBRARIES'])
  unless find_executable('gpgme-config')
    $stderr.puts("gpgme-config not found")
    exit(1)
  end

  $CFLAGS += ' ' << `gpgme-config --cflags`.chomp
  $libs += ' ' << `gpgme-config --libs`.chomp
else
  # borrowed from Nokogiri
  def message!(important_message)
    message important_message
    if !$stdout.tty? && File.chardev?('/dev/tty')
      File.open('/dev/tty', 'w') { |tty|
        tty.print important_message
      }
    end
  end

  message! <<-'EOS'
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
  require 'mini_portile'

  libgpg_error_recipe = MiniPortile.new('libgpg-error', '1.12').tap do |recipe|
    recipe.target = File.join(ROOT, "ports")
    recipe.files = ["ftp://ftp.gnupg.org/gcrypt/#{recipe.name}/#{recipe.name}-#{recipe.version}.tar.bz2"]
    recipe.configure_options = [
      '--disable-shared',
      '--enable-static',
      '--disable-nls',
      "CFLAGS='-fPIC #{ENV["CFLAGS"]}'",
    ]
    checkpoint = "#{recipe.target}/#{recipe.name}-#{recipe.version}-#{recipe.host}.installed"
    unless File.exist?(checkpoint)
      recipe.cook
      FileUtils.touch checkpoint
    end
    recipe.activate
  end

  libassuan_recipe = MiniPortile.new('libassuan', '2.1.1').tap do |recipe|
    recipe.target = File.join(ROOT, "ports")
    recipe.files = ["ftp://ftp.gnupg.org/gcrypt/#{recipe.name}/#{recipe.name}-#{recipe.version}.tar.bz2"]
    recipe.configure_options = [
      '--disable-shared',
      '--enable-static',
      "--with-gpg-error-prefix=#{libgpg_error_recipe.path}",
      "CFLAGS='-fPIC #{ENV["CFLAGS"]}'",
    ]
    checkpoint = "#{recipe.target}/#{recipe.name}-#{recipe.version}-#{recipe.host}.installed"
    unless File.exist?(checkpoint)
      recipe.cook
      FileUtils.touch checkpoint
    end
    recipe.activate
  end

  gpgme_recipe = MiniPortile.new('gpgme', '1.4.3').tap do |recipe|
    recipe.target = File.join(ROOT, "ports")
    recipe.files = ["ftp://ftp.gnupg.org/gcrypt/#{recipe.name}/#{recipe.name}-#{recipe.version}.tar.bz2"]
    recipe.configure_options = [
      '--disable-shared',
      '--enable-static',
      "--with-gpg-error-prefix=#{libgpg_error_recipe.path}",
      "--with-libassuan-prefix=#{libassuan_recipe.path}",
      "CFLAGS='-fPIC #{ENV["CFLAGS"]}'",
    ]
    checkpoint = "#{recipe.target}/#{recipe.name}-#{recipe.version}-#{recipe.host}.installed"
    unless File.exist?(checkpoint)
      recipe.cook
      FileUtils.touch checkpoint
    end
    recipe.activate
  end

  # special treatment to link with static libraries
  # borrowed from Nokogiri
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
        when /\A-l./
          libs.push(arg)
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
