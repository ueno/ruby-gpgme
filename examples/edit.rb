#!/usr/bin/env ruby
require 'gpgme'

# If you do not have gpg-agent installed, comment out the following
# and set it as :passphrase_callback.
#
# def passfunc(hook, uid_hint, passphrase_info, prev_was_bad, fd)
#   $stderr.write("Passphrase for #{uid_hint}: ")
#   $stderr.flush
#   begin
#     system('stty -echo')
#     io = IO.for_fd(fd, 'w')
#     io.puts(gets)
#     io.flush
#   ensure
#     (0 ... $_.length).each do |i| $_[i] = ?0 end if $_
#     system('stty echo')
#   end
#   $stderr.puts
# end

unless ENV['GPG_AGENT_INFO']
  $stderr.puts("gpg-agent is not running.  See the comment in #{$0}.")
  exit(1)
end

unless ENV['GNUPGHOME']
  $stderr.write('As GNUPGHOME is not set, the generated key pair will be stored into *your* keyring.  Really proceed? (y/N) ')
  $stderr.flush
  exit(1) unless gets.chomp == 'y'
end

unless ARGV.length == 1
  $stderr.puts("Usage: #{$0} KEYGRIP")
  exit(1)
end

def progfunc(hook, what, type, current, total)
  $stderr.write("#{what}: #{current}/#{total}\r")
  $stderr.flush
end

# Callback function for key editing.
#
# For GPGME 2.0.0+:
#   The callback receives (hook, keyword, args, fd) where keyword is a string
#   like "GET_BOOL", "GET_LINE", "GET_HIDDEN", "GOT_IT", etc.
#
# For GPGME < 2.0.0:
#   The callback receives (hook, status, args, fd) where status is a numeric
#   constant like GPGME::GPGME_STATUS_GET_BOOL, GPGME::GPGME_STATUS_GET_LINE, etc.
#
def editfunc(hook, status_or_keyword, args, fd)
  # Determine if we're using GPGME 2.0.0+ (string keyword) or older (numeric status)
  if status_or_keyword.is_a?(String)
    # GPGME 2.0.0+: keyword is a string
    keyword = status_or_keyword
    case keyword
    when "GET_BOOL"
      begin
        $stderr.write("#{args} (y/n) ")
        $stderr.flush
        line = gets
      end until line =~ /\A\s*[ny]\s*\z/
      io = IO.for_fd(fd)
      io.puts(line.strip)
      io.flush
    when "GET_LINE", "GET_HIDDEN"
      $stderr.write("#{args}: ")
      $stderr.flush
      line = gets
      io = IO.for_fd(fd)
      io.puts(line)
      io.flush
    else
      $stderr.puts([keyword, args].inspect)
    end
  else
    # GPGME < 2.0.0: status is a numeric constant
    status = status_or_keyword
    case status
    when GPGME::GPGME_STATUS_GET_BOOL
      begin
        $stderr.write("#{args} (y/n) ")
        $stderr.flush
        line = gets
      end until line =~ /\A\s*[ny]\s*\z/
      io = IO.for_fd(fd)
      io.puts(line.strip)
      io.flush
    when GPGME::GPGME_STATUS_GET_LINE, GPGME::GPGME_STATUS_GET_HIDDEN
      $stderr.write("#{args}: ")
      $stderr.flush
      line = gets
      io = IO.for_fd(fd)
      io.puts(line)
      io.flush
    else
      $stderr.puts([status, args].inspect)
    end
  end
end

ctx = GPGME::Ctx.new({:progress_callback => method(:progfunc),
		       # :passphrase_callback => method(:passfunc)
		     })
keystr = ARGV.shift
keys = ctx.keys(keystr)
if keys.empty?
  $stderr.puts("Can't find key for \"#{keystr}\"")
  exit(1)
end

$stderr.puts(keys.first.inspect)
ctx.edit_key(keys.first, method(:editfunc))
