=begin rdoc
= What's this?

Ruby-GPGME is a Ruby language binding of GPGME (GnuPG Made Easy).

= Requirements

- Ruby 1.8 or later
- GPGME 1.1.2 or later http://www.gnupg.org/(en)/related_software/gpgme/index.html
- gpg-agent (optional, but recommended)

= Installation

 $ gem install ruby-gpgme

or

 $ ruby extconf.rb
 $ make
 $ make install

= Examples

<tt>examples/genkey.rb</tt>::	Generate a key pair in your keyring.
<tt>examples/keylist.rb</tt>::	List your keyring like gpg --list-keys.
<tt>examples/roundtrip.rb</tt>::  Encrypt and decrypt a plain text.
<tt>examples/sign.rb</tt>::	Create a clear text signature.
<tt>examples/verify.rb</tt>::	Verify a clear text signature given from stdin.

= API

Ruby-GPGME provides three levels of API.  The highest level API is
close to the command line interface of GnuPG.  The mid level API looks
object-oriented (or rubyish).  The lowest level API is close to the C
interface of GPGME.

== The highest level API

It can be written in the highest level API to create a cleartext
signature of the plaintext from stdin as follows.

 $ ruby -rgpgme -e 'GPGME.clearsign($stdin, $stdout)'

== The mid level API

The same example can be rewritten in the mid level API as follows.

 $ ruby -rgpgme -e <<End  
 ctx = GPGME::Ctx.new
 plain = GPGME::Data.from_io($stdin)
 sig = GPGME::Data.from_io($stdout)
 ctx.sign(plain, sig, GPGME::SIG_MODE_CLEAR)
 End

== The lowest level API

The same example can be rewritten in the lowest level API as follows.

 $ ruby -rgpgme -e <<End  
 ret = Array.new
 GPGME::gpgme_new(ret)
 ctx = ret.shift
 GPGME::gpgme_data_new_from_fd(ret, 0)
 plain = ret.shift
 GPGME::gpgme_data_new_from_fd(ret, 1)
 sig = ret.shift
 GPGME::gpgme_op_sign(ctx, plain, sig, GPGME::SIG_MODE_CLEAR)
 End

As you see, it's much harder to write a program in this API than the
higher level API.  However, if you are already familier with the C
interface of GPGME and/or want to control detailed behavior of GPGME,
it might be useful.

= License

Copyright (C) 2003,2006,2007,2008,2009 Daiki Ueno

This file is a part of Ruby-GPGME.

Ruby-GPGME is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

Ruby-GPGME is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
=end
module GPGME
  VERSION = "1.0.8"
end

require 'gpgme_n'
require 'gpgme/constants'

# call-seq:
#   GPGME.decrypt(cipher, plain=nil, options=Hash.new){|signature| ...}
#
# <code>GPGME.decrypt</code> performs decryption.
#
# The arguments should be specified as follows.
# 
# - GPGME.decrypt(<i>cipher</i>, <i>plain</i>, <i>options</i>)
# - GPGME.decrypt(<i>cipher</i>, <i>options</i>) -> <i>plain</i>
#
# All arguments except <i>cipher</i> are optional.  <i>cipher</i> is
# input, and <i>plain</i> is output.  If the last argument is a
# Hash, options will be read from it.
#
# An input argument is specified by an IO like object (which responds
# to <code>read</code>), a string, or a GPGME::Data object.
#
# An output argument is specified by an IO like object (which responds
# to <code>write</code>) or a GPGME::Data object.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
#
def GPGME.decrypt(cipher, *args_options)
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
  args, options = split_args(args_options)
  plain = args[0]

  check_version(options)
  GPGME::Ctx.new(options) do |ctx|
    cipher_data = input_data(cipher)
    plain_data = output_data(plain)
    begin
      ctx.decrypt_verify(cipher_data, plain_data)
    rescue GPGME::Error::UnsupportedAlgorithm => exc
      exc.algorithm = ctx.decrypt_result.unsupported_algorithm
      raise exc
    rescue GPGME::Error::WrongKeyUsage => exc
      exc.key_usage = ctx.decrypt_result.wrong_key_usage
      raise exc
    end

    verify_result = ctx.verify_result
    if verify_result && block_given?
      verify_result.signatures.each do |signature|
        yield signature
      end
    end

    unless plain
      plain_data.seek(0, IO::SEEK_SET)
      plain_data.read
    end
  end
end

# call-seq:
#   GPGME.verify(sig, signed_text=nil, plain=nil, options=Hash.new){|signature| ...}
#
# <code>GPGME.verify</code> verifies a signature.
#
# The arguments should be specified as follows.
# 
# - GPGME.verify(<i>sig</i>, <i>signed_text</i>, <i>plain</i>, <i>options</i>)
# - GPGME.verify(<i>sig</i>, <i>signed_text</i>, <i>options</i>) -> <i>plain</i>
#
# All arguments except <i>sig</i> are optional.  <i>sig</i> and
# <i>signed_text</i> are input.  <i>plain</i> is output.  If the last
# argument is a Hash, options will be read from it.
#
# An input argument is specified by an IO like object (which responds
# to <code>read</code>), a string, or a GPGME::Data object.
#
# An output argument is specified by an IO like object (which responds
# to <code>write</code>) or a GPGME::Data object.
#
# If <i>sig</i> is a detached signature, then the signed text should
# be provided in <i>signed_text</i> and <i>plain</i> should be
# <tt>nil</tt>.  Otherwise, if <i>sig</i> is a normal (or cleartext)
# signature, <i>signed_text</i> should be <tt>nil</tt>.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
#
def GPGME.verify(sig, *args_options) # :yields: signature
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
  args, options = split_args(args_options)
  signed_text, plain = args

  check_version(options)
  GPGME::Ctx.new(options) do |ctx|
    sig_data = input_data(sig)
    if signed_text
      signed_text_data = input_data(signed_text)
      plain_data = nil
    else
      signed_text_data = nil
      plain_data = output_data(plain)
    end
    ctx.verify(sig_data, signed_text_data, plain_data)
    ctx.verify_result.signatures.each do |signature|
      yield signature
    end
    if !signed_text && !plain
      plain_data.seek(0, IO::SEEK_SET)
      plain_data.read
    end
  end
end

# call-seq:
#   GPGME.sign(plain, sig=nil, options=Hash.new)
#
# <code>GPGME.sign</code> creates a signature of the plaintext.
#
# The arguments should be specified as follows.
# 
# - GPGME.sign(<i>plain</i>, <i>sig</i>, <i>options</i>)
# - GPGME.sign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
#
# All arguments except <i>plain</i> are optional.  <i>plain</i> is
# input and <i>sig</i> is output.  If the last argument is a Hash,
# options will be read from it.
#
# An input argument is specified by an IO like object (which responds
# to <code>read</code>), a string, or a GPGME::Data object.
#
# An output argument is specified by an IO like object (which responds
# to <code>write</code>) or a GPGME::Data object.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
#
# - <tt>:signers</tt> Signing keys.  If specified, it is an array
#   whose elements are a GPGME::Key object or a string.
# - <tt>:mode</tt> Desired type of a signature.  Either
#   <tt>GPGME::SIG_MODE_NORMAL</tt> for a normal signature,
#   <tt>GPGME::SIG_MODE_DETACH</tt> for a detached signature, or
#   <tt>GPGME::SIG_MODE_CLEAR</tt> for a cleartext signature.
#
def GPGME.sign(plain, *args_options)
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
  args, options = split_args(args_options)
  sig = args[0]

  check_version(options)
  GPGME::Ctx.new(options) do |ctx|
    ctx.add_signer(*resolve_keys(options[:signers], true, [:sign])) if options[:signers]
    mode = options[:mode] || GPGME::SIG_MODE_NORMAL
    plain_data = input_data(plain)
    sig_data = output_data(sig)
    begin
      ctx.sign(plain_data, sig_data, mode)
    rescue GPGME::Error::UnusableSecretKey => exc
      exc.keys = ctx.sign_result.invalid_signers
      raise exc
    end

    unless sig
      sig_data.seek(0, IO::SEEK_SET)
      sig_data.read
    end
  end
end

# call-seq:
#   GPGME.clearsign(plain, sig=nil, options=Hash.new)
#
# <code>GPGME.clearsign</code> creates a cleartext signature of the plaintext.
#
# The arguments should be specified as follows.
# 
# - GPGME.clearsign(<i>plain</i>, <i>sig</i>, <i>options</i>)
# - GPGME.clearsign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
#
# All arguments except <i>plain</i> are optional.  <i>plain</i> is
# input and <i>sig</i> is output.  If the last argument is a Hash,
# options will be read from it.
#
# An input argument is specified by an IO like object (which responds
# to <code>read</code>), a string, or a GPGME::Data object.
#
# An output argument is specified by an IO like object (which responds
# to <code>write</code>) or a GPGME::Data object.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
#
# - <tt>:signers</tt> Signing keys.  If specified, it is an array
#   whose elements are a GPGME::Key object or a string.
#
def GPGME.clearsign(plain, *args_options)
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
  args, options = split_args(args_options)
  args.push(options.merge({:mode => GPGME::SIG_MODE_CLEAR}))
  GPGME.sign(plain, *args)
end

# call-seq:
#   GPGME.detach_sign(plain, sig=nil, options=Hash.new)
#
# <code>GPGME.detach_sign</code> creates a detached signature of the plaintext.
#
# The arguments should be specified as follows.
# 
# - GPGME.detach_sign(<i>plain</i>, <i>sig</i>, <i>options</i>)
# - GPGME.detach_sign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
#
# All arguments except <i>plain</i> are optional.  <i>plain</i> is
# input and <i>sig</i> is output.  If the last argument is a Hash,
# options will be read from it.
#
# An input argument is specified by an IO like object (which responds
# to <code>read</code>), a string, or a GPGME::Data object.
#
# An output argument is specified by an IO like object (which responds
# to <code>write</code>) or a GPGME::Data object.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
#
# - <tt>:signers</tt> Signing keys.  If specified, it is an array
#   whose elements are a GPGME::Key object or a string.
#
def GPGME.detach_sign(plain, *args_options)
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
  args, options = split_args(args_options)
  args.push(options.merge({:mode => GPGME::SIG_MODE_DETACH}))
  GPGME.sign(plain, *args)
end

# call-seq:
#   GPGME.encrypt(recipients, plain, cipher=nil, options=Hash.new)
#
# <code>GPGME.encrypt</code> performs encryption.
#
# The arguments should be specified as follows.
# 
# - GPGME.encrypt(<i>recipients</i>, <i>plain</i>, <i>cipher</i>, <i>options</i>)
# - GPGME.encrypt(<i>recipients</i>, <i>plain</i>, <i>options</i>) -> <i>cipher</i>
#
# All arguments except <i>recipients</i> and <i>plain</i> are
# optional.  <i>plain</i> is input and <i>cipher</i> is output.  If
# the last argument is a Hash, options will be read from it.
#
# The recipients are specified by an array whose elements are a string
# or a GPGME::Key object.  If <i>recipients</i> is <tt>nil</tt>, it
# performs symmetric encryption.
#
# An input argument is specified by an IO like object (which responds
# to <code>read</code>), a string, or a GPGME::Data object.
#
# An output argument is specified by an IO like object (which responds
# to <code>write</code>) or a GPGME::Data object.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
#
# - <tt>:sign</tt> If <tt>true</tt>, it performs a combined sign and
#   encrypt operation.
# - <tt>:signers</tt> Signing keys.  If specified, it is an array
#   whose elements are a GPGME::Key object or a string.
# - <tt>:always_trust</tt> Setting this to <tt>true</tt> specifies all
#   the recipients should be trusted.
#
def GPGME.encrypt(recipients, plain, *args_options)
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
  args, options = split_args(args_options)
  cipher = args[0]
  recipient_keys = recipients ? resolve_keys(recipients, false, [:encrypt]) : nil

  check_version(options)
  GPGME::Ctx.new(options) do |ctx|
    plain_data = input_data(plain)
    cipher_data = output_data(cipher)
    begin
      flags = 0
      if options[:always_trust]
        flags |= GPGME::ENCRYPT_ALWAYS_TRUST
      end
      if options[:sign]
        if options[:signers]
          ctx.add_signer(*resolve_keys(options[:signers], true, [:sign]))
        end
        ctx.encrypt_sign(recipient_keys, plain_data, cipher_data, flags)
      else
        ctx.encrypt(recipient_keys, plain_data, cipher_data, flags)
      end
    rescue GPGME::Error::UnusablePublicKey => exc
      exc.keys = ctx.encrypt_result.invalid_recipients
      raise exc
    rescue GPGME::Error::UnusableSecretKey => exc
      exc.keys = ctx.sign_result.invalid_signers
      raise exc
    end

    unless cipher
      cipher_data.seek(0, IO::SEEK_SET)
      cipher_data.read
    end
  end
end

# call-seq:
#   GPGME.list_keys(pattern=nil, secret_only=false, options=Hash.new){|key| ...}
#
# <code>GPGME.list_keys</code> iterates over the key ring.
#
# The arguments should be specified as follows.
# 
# - GPGME.list_keys(<i>pattern</i>, <i>secret_only</i>, <i>options</i>)
#
# All arguments are optional.  If the last argument is a Hash, options
# will be read from it.
#
# <i>pattern</i> is a string or <tt>nil</tt>.  If <i>pattern</i> is
# <tt>nil</tt>, all available keys are returned.  If
# <i>secret_only</i> is <tt>true</tt>, the only secret keys are
# returned.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
#
def GPGME.list_keys(*args_options) # :yields: key
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
  args, options = split_args(args_options)
  pattern, secret_only = args
  check_version(options)
  GPGME::Ctx.new do |ctx|
    if block_given?  
      ctx.each_key(pattern, secret_only || false) do |key|
        yield key
      end
    else
      ctx.keys(pattern, secret_only || false)
    end
  end
end

# call-seq:
#   GPGME.export(pattern)
#
# <code>GPGME.export</code> extracts public keys from the key ring.
#
# The arguments should be specified as follows.
# 
# - GPGME.export(<i>pattern</i>, <i>options</i>) -> <i>keydata</i>
# - GPGME.export(<i>pattern</i>, <i>keydata</i>, <i>options</i>)
#
# All arguments are optional.  If the last argument is a Hash, options
# will be read from it.
#
# <i>pattern</i> is a string or <tt>nil</tt>.  If <i>pattern</i> is
# <tt>nil</tt>, all available public keys are returned.
# <i>keydata</i> is output.
#
# An output argument is specified by an IO like object (which responds
# to <code>write</code>) or a GPGME::Data object.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
#
def GPGME.export(*args_options)
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
  args, options = split_args(args_options)
  pattern, key = args[0]
  key_data = output_data(key)
  check_version(options)
  GPGME::Ctx.new(options) do |ctx|
    ctx.export_keys(pattern, key_data)

    unless key
      key_data.seek(0, IO::SEEK_SET)
      key_data.read
    end
  end
end

# call-seq:
#   GPGME.import(keydata)
#
# <code>GPGME.import</code> adds the keys to the key ring.
#
# The arguments should be specified as follows.
# 
# - GPGME.import(<i>keydata</i>, <i>options</i>)
#
# All arguments are optional.  If the last argument is a Hash, options
# will be read from it.
#
# <i>keydata</i> is input.
#
# An input argument is specified by an IO like object (which responds
# to <code>read</code>), a string, or a GPGME::Data object.
#
# <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
#
def GPGME.import(*args_options)
  raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
  args, options = split_args(args_options)
  key = args[0]
  key_data = input_data(key)
  check_version(options)
  GPGME::Ctx.new(options) do |ctx|
    ctx.import_keys(key_data)
    ctx.import_result
  end
end

module GPGME
  # :stopdoc:
  private

  def split_args(args_options)
    if args_options.length > 0 and args_options[-1].respond_to? :to_hash
      args = args_options[0 ... -1]
      options = args_options[-1].to_hash
    else
      args = args_options
      options = Hash.new
    end
    [args, options]
  end
  module_function :split_args

  def check_version(options = nil)
    version = nil
    if options.kind_of?(String)
      version = options
    elsif options.include?(:version)
      version = options[:version]
    end
    unless GPGME::gpgme_check_version(version)
      raise Error::InvalidVersion.new
    end
  end
  module_function :check_version

  def resolve_keys(keys_or_names, secret_only, purposes = Array.new)
    keys = Array.new
    keys_or_names.each do |key_or_name|
      if key_or_name.kind_of? Key
        keys << key_or_name
      elsif key_or_name.kind_of? String
        GPGME::Ctx.new do |ctx|
          key = ctx.keys(key_or_name, secret_only).find {|k|
            k.usable_for?(purposes)
          }
          keys << key if key
        end
      end
    end
    keys
  end
  module_function :resolve_keys

  def input_data(input)
    if input.kind_of? GPGME::Data
      input
    elsif input.respond_to? :to_str
      GPGME::Data.from_str(input.to_str)
    elsif input.respond_to? :read
      GPGME::Data.from_callbacks(IOCallbacks.new(input))
    else
      raise ArgumentError, input.inspect
    end
  end
  module_function :input_data

  def output_data(output)
    if output.kind_of? GPGME::Data
      output
    elsif output.respond_to? :write
      GPGME::Data.from_callbacks(IOCallbacks.new(output))
    elsif !output
      GPGME::Data.empty
    else
      raise ArgumentError, output.inspect
    end
  end
  module_function :output_data

  class IOCallbacks
    def initialize(io)
      @io = io
    end

    def read(hook, length)
      @io.read(length)
    end

    def write(hook, buffer, length)
      @io.write(buffer[0 .. length])
    end

    def seek(hook, offset, whence)
      return @io.pos if offset == 0 && whence == IO::SEEK_CUR
      @io.seek(offset, whence)
      @io.pos
    end
  end

  PROTOCOL_NAMES = {
    PROTOCOL_OpenPGP => :OpenPGP,
    PROTOCOL_CMS => :CMS
  }

  KEYLIST_MODE_NAMES = {
    KEYLIST_MODE_LOCAL => :local,
    KEYLIST_MODE_EXTERN => :extern,
    KEYLIST_MODE_SIGS => :sigs,
    KEYLIST_MODE_VALIDATE => :validate
  }

  VALIDITY_NAMES = {
    VALIDITY_UNKNOWN => :unknown,
    VALIDITY_UNDEFINED => :undefined,
    VALIDITY_NEVER => :never,
    VALIDITY_MARGINAL => :marginal,
    VALIDITY_FULL => :full,
    VALIDITY_ULTIMATE => :ultimate
  }
  # :startdoc:
end

module GPGME
  class Error < StandardError
    def initialize(error)
      @error = error
    end
    attr_reader :error

    # Return the error code.
    #
    # The error code indicates the type of an error, or the reason why
    # an operation failed.
    def code
      GPGME::gpgme_err_code(@error)
    end

    # Return the error source.
    #
    # The error source has not a precisely defined meaning.  Sometimes
    # it is the place where the error happened, sometimes it is the
    # place where an error was encoded into an error value.  Usually
    # the error source will give an indication to where to look for
    # the problem.  This is not always true, but it is attempted to
    # achieve this goal.
    def source
      GPGME::gpgme_err_source(@error)
    end

    # Return a description of the error code.
    def message
      GPGME::gpgme_strerror(@error)
    end

    class General < self; end
    class InvalidValue < self; end
    class UnusablePublicKey < self
      attr_accessor :keys
    end
    class UnusableSecretKey < self
      attr_accessor :keys
    end
    class NoData < self; end
    class Conflict < self; end
    class NotImplemented < self; end
    class DecryptFailed < self; end
    class BadPassphrase < self; end
    class Canceled < self; end
    class InvalidEngine < self; end
    class AmbiguousName < self; end
    class WrongKeyUsage < self
      attr_accessor :key_usage
    end
    class CertificateRevoked < self; end
    class CertificateExpired < self; end
    class NoCRLKnown < self; end
    class NoPolicyMatch < self; end
    class NoSecretKey < self; end
    class MissingCertificate < self; end
    class BadCertificateChain < self; end
    class UnsupportedAlgorithm < self
      attr_accessor :algorithm
    end
    class BadSignature < self; end
    class NoPublicKey < self; end
    class InvalidVersion < self; end
  end

  def error_to_exception(err)   # :nodoc:
    case GPGME::gpgme_err_code(err)
    when GPG_ERR_EOF
      EOFError.new
    when GPG_ERR_NO_ERROR
      nil
    when GPG_ERR_GENERAL
      Error::General.new(err)
    when GPG_ERR_ENOMEM
      Errno::ENOMEM.new
    when GPG_ERR_INV_VALUE
      Error::InvalidValue.new(err)
    when GPG_ERR_UNUSABLE_PUBKEY
      Error::UnusablePublicKey.new(err)
    when GPG_ERR_UNUSABLE_SECKEY
      Error::UnusableSecretKey.new(err)
    when GPG_ERR_NO_DATA
      Error::NoData.new(err)
    when GPG_ERR_CONFLICT
      Error::Conflict.new(err)
    when GPG_ERR_NOT_IMPLEMENTED
      Error::NotImplemented.new(err)
    when GPG_ERR_DECRYPT_FAILED
      Error::DecryptFailed.new(err)
    when GPG_ERR_BAD_PASSPHRASE
      Error::BadPassphrase.new(err)
    when GPG_ERR_CANCELED
      Error::Canceled.new(err)
    when GPG_ERR_INV_ENGINE
      Error::InvalidEngine.new(err)
    when GPG_ERR_AMBIGUOUS_NAME
      Error::AmbiguousName.new(err)
    when GPG_ERR_WRONG_KEY_USAGE
      Error::WrongKeyUsage.new(err)
    when GPG_ERR_CERT_REVOKED
      Error::CertificateRevoked.new(err)
    when GPG_ERR_CERT_EXPIRED
      Error::CertificateExpired.new(err)
    when GPG_ERR_NO_CRL_KNOWN
      Error::NoCRLKnown.new(err)
    when GPG_ERR_NO_POLICY_MATCH
      Error::NoPolicyMatch.new(err)
    when GPG_ERR_NO_SECKEY
      Error::NoSecretKey.new(err)
    when GPG_ERR_MISSING_CERT
      Error::MissingCertificate.new(err)
    when GPG_ERR_BAD_CERT_CHAIN
      Error::BadCertificateChain.new(err)
    when GPG_ERR_UNSUPPORTED_ALGORITHM
      Error::UnsupportedAlgorithm.new(err)
    when GPG_ERR_BAD_SIGNATURE
      Error::BadSignature.new(err)
    when GPG_ERR_NO_PUBKEY
      Error::NoPublicKey.new(err)
    else
      Error.new(err)
    end
  end
  module_function :error_to_exception
  private :error_to_exception

  class << self
    alias pubkey_algo_name gpgme_pubkey_algo_name
    alias hash_algo_name gpgme_hash_algo_name
  end

  # Verify that the engine implementing the protocol <i>proto</i> is
  # installed in the system.
  def engine_check_version(proto)
    err = GPGME::gpgme_engine_check_version(proto)
    exc = GPGME::error_to_exception(err)
    raise exc if exc
  end
  module_function :engine_check_version

  # Return a list of info structures of enabled engines.
  def engine_info
    rinfo = Array.new
    GPGME::gpgme_get_engine_info(rinfo)
    rinfo
  end
  module_function :engine_info

  # Change the default configuration of the crypto engine implementing
  # protocol <i>proto</i>.
  #
  # <i>file_name</i> is the file name of the executable program
  # implementing the protocol.
  # <i>home_dir</i> is the directory name of the configuration directory.
  def set_engine_info(proto, file_name, home_dir)
    err = GPGME::gpgme_set_engine_info(proto, file_name, home_dir)
    exc = GPGME::error_to_exception(err)
    raise exc if exc
  end
  module_function :set_engine_info

  # A class for managing data buffers.
  class Data
    BLOCK_SIZE = 4096

    # Create a new instance.
    #
    # The created data types depend on <i>arg</i>.  If <i>arg</i> is
    # <tt>nil</tt>, it creates an instance with an empty buffer.
    # Otherwise, <i>arg</i> is either a string, an IO, or a Pathname.
    def self.new(arg = nil, copy = false)
      if arg.nil?
        return empty
      elsif arg.respond_to? :to_str
        return from_str(arg.to_str, copy)
      elsif arg.respond_to? :to_io
        return from_io(arg.to_io)
      elsif arg.respond_to? :open
        return from_io(arg.open)
      end
    end

    # Create a new instance with an empty buffer.
    def self.empty
      rdh = Array.new
      err = GPGME::gpgme_data_new(rdh)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance with internal buffer.
    def self.from_str(buf, copy = true)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_mem(rdh, buf, buf.length)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance associated with a given IO.
    def self.from_io(io)
      from_callbacks(IOCallbacks.new(arg))
    end

    # Create a new instance from the specified file descriptor.
    def self.from_fd(fd)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_fd(rdh, fd)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance from the specified callbacks.
    def self.from_callbacks(callbacks, hook_value = nil)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_cbs(rdh, callbacks, hook_value)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Read at most <i>length</i> bytes from the data object, or to the end
    # of file if <i>length</i> is omitted or is <tt>nil</tt>.
    def read(length = nil)
      if length
	GPGME::gpgme_data_read(self, length)
      else
	buf = String.new
        loop do
          s = GPGME::gpgme_data_read(self, BLOCK_SIZE)
          break unless s
          buf << s
        end
        buf
      end
    end

    # Seek to a given <i>offset</i> in the data object according to the
    # value of <i>whence</i>.
    def seek(offset, whence = IO::SEEK_SET)
      GPGME::gpgme_data_seek(self, offset, IO::SEEK_SET)
    end

    # Write <i>length</i> bytes from <i>buffer</i> into the data object.
    def write(buffer, length = buffer.length)
      GPGME::gpgme_data_write(self, buffer, length)
    end

    # Return the encoding of the underlying data.
    def encoding
      GPGME::gpgme_data_get_encoding(self)
    end

    # Set the encoding to a given <i>encoding</i> of the underlying
    # data object.
    def encoding=(encoding)
      err = GPGME::gpgme_data_set_encoding(self, encoding)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      encoding
    end
  end

  class EngineInfo
    private_class_method :new
    
    attr_reader :protocol, :file_name, :version, :req_version, :home_dir
    alias required_version req_version
  end

  # A context within which all cryptographic operations are performed.
  class Ctx
    # Create a new instance from the given <i>options</i>.
    # <i>options</i> is a Hash whose keys are
    #
    # * <tt>:protocol</tt>  Either <tt>PROTOCOL_OpenPGP</tt> or
    #   <tt>PROTOCOL_CMS</tt>.
    #
    # * <tt>:armor</tt>  If <tt>true</tt>, the output should be ASCII armored.
    #
    # * <tt>:textmode</tt>  If <tt>true</tt>, inform the recipient that the
    #   input is text.
    #
    # * <tt>:keylist_mode</tt>  Either
    #   <tt>KEYLIST_MODE_LOCAL</tt>,
    #   <tt>KEYLIST_MODE_EXTERN</tt>,
    #   <tt>KEYLIST_MODE_SIGS</tt>, or
    #   <tt>KEYLIST_MODE_VALIDATE</tt>.
    # * <tt>:passphrase_callback</tt>  A callback function.
    # * <tt>:passphrase_callback_value</tt> An object passed to
    #   passphrase_callback.
    # * <tt>:progress_callback</tt>  A callback function.
    # * <tt>:progress_callback_value</tt> An object passed to
    #   progress_callback.
    #
    def self.new(options = Hash.new)
      rctx = Array.new
      err = GPGME::gpgme_new(rctx)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      ctx = rctx[0]
      options.each_pair do |key, value|
        case key
        when :protocol
          ctx.protocol = value
        when :armor
          ctx.armor = value
        when :textmode
          ctx.textmode = value
        when :keylist_mode
          ctx.keylist_mode = value
        when :passphrase_callback
          ctx.set_passphrase_callback(value,
                                      options[:passphrase_callback_value])
        when :progress_callback
          ctx.set_progress_callback(value,
                                      options[:progress_callback_value])
        end
      end
      if block_given?
        begin
          yield ctx
        ensure
          GPGME::gpgme_release(ctx)
        end
      else
        ctx
      end
    end

    # Set the <i>protocol</i> used within this context.
    def protocol=(proto)
      err = GPGME::gpgme_set_protocol(self, proto)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      proto
    end

    # Return the protocol used within this context.
    def protocol
      GPGME::gpgme_get_protocol(self)
    end

    # Tell whether the output should be ASCII armored.
    def armor=(yes)
      GPGME::gpgme_set_armor(self, yes ? 1 : 0)
      yes
    end

    # Return true if the output is ASCII armored.
    def armor
      GPGME::gpgme_get_armor(self) == 1 ? true : false
    end

    # Tell whether canonical text mode should be used.
    def textmode=(yes)
      GPGME::gpgme_set_textmode(self, yes ? 1 : 0)
      yes
    end

    # Return true if canonical text mode is enabled.
    def textmode
      GPGME::gpgme_get_textmode(self) == 1 ? true : false
    end

    # Change the default behaviour of the key listing functions.
    def keylist_mode=(mode)
      GPGME::gpgme_set_keylist_mode(self, mode)
      mode
    end

    # Return the current key listing mode.
    def keylist_mode
      GPGME::gpgme_get_keylist_mode(self)
    end

    def inspect
      "#<#{self.class} protocol=#{PROTOCOL_NAMES[protocol] || protocol}, \
armor=#{armor}, textmode=#{textmode}, \
keylist_mode=#{KEYLIST_MODE_NAMES[keylist_mode]}>"
    end

    # Set the passphrase callback with given hook value.
    # <i>passfunc</i> should respond to <code>call</code> with 5 arguments.
    #
    #  def passfunc(hook, uid_hint, passphrase_info, prev_was_bad, fd)
    #    $stderr.write("Passphrase for #{uid_hint}: ")
    #    $stderr.flush
    #    begin
    #      system('stty -echo')
    #      io = IO.for_fd(fd, 'w')
    #      io.puts(gets)
    #      io.flush
    #    ensure
    #      (0 ... $_.length).each do |i| $_[i] = ?0 end if $_
    #      system('stty echo')
    #    end
    #    $stderr.puts
    #  end
    #
    #  ctx.set_passphrase_callback(method(:passfunc))
    #
    def set_passphrase_callback(passfunc, hook_value = nil)
      GPGME::gpgme_set_passphrase_cb(self, passfunc, hook_value)
    end
    alias set_passphrase_cb set_passphrase_callback

    # Set the progress callback with given hook value.
    # <i>progfunc</i> should respond to <code>call</code> with 5 arguments.
    #
    #  def progfunc(hook, what, type, current, total)
    #    $stderr.write("#{what}: #{current}/#{total}\r")
    #    $stderr.flush
    #  end
    #
    #  ctx.set_progress_callback(method(:progfunc))
    #
    def set_progress_callback(progfunc, hook_value = nil)
      GPGME::gpgme_set_progress_cb(self, progfunc, hook_value)
    end
    alias set_progress_cb set_progress_callback

    # Initiate a key listing operation for given pattern.
    # If <i>pattern</i> is <tt>nil</tt>, all available keys are
    # returned.  If <i>secret_only</i> is <tt>true</tt>, the only
    # secret keys are returned.
    def keylist_start(pattern = nil, secret_only = false)
      err = GPGME::gpgme_op_keylist_start(self, pattern, secret_only ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Advance to the next key in the key listing operation.
    def keylist_next
      rkey = Array.new
      err = GPGME::gpgme_op_keylist_next(self, rkey)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rkey[0]
    end

    # End a pending key list operation.
    def keylist_end
      err = GPGME::gpgme_op_keylist_end(self)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Convenient method to iterate over keys.
    # If <i>pattern</i> is <tt>nil</tt>, all available keys are
    # returned.  If <i>secret_only</i> is <tt>true</tt>, the only
    # secret keys are returned.
    def each_key(pattern = nil, secret_only = false, &block) # :yields: key
      keylist_start(pattern, secret_only)
      begin
	loop do
	  yield keylist_next
	end
        keys
      rescue EOFError
	# The last key in the list has already been returned.
      ensure
	keylist_end
      end
    end
    alias each_keys each_key

    def keys(pattern = nil, secret_only = nil)
      keys = Array.new
      each_key(pattern, secret_only) do |key|
        keys << key
      end
      keys
    end

    # Get the key with the <i>fingerprint</i>.
    # If <i>secret</i> is <tt>true</tt>, secret key is returned.
    def get_key(fingerprint, secret = false)
      rkey = Array.new
      err = GPGME::gpgme_get_key(self, fingerprint, rkey, secret ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rkey[0]
    end

    # Generate a new key pair.
    # <i>parms</i> is a string which looks like
    #
    #  <GnupgKeyParms format="internal">
    #  Key-Type: DSA
    #  Key-Length: 1024
    #  Subkey-Type: ELG-E
    #  Subkey-Length: 1024
    #  Name-Real: Joe Tester
    #  Name-Comment: with stupid passphrase
    #  Name-Email: joe@foo.bar
    #  Expire-Date: 0
    #  Passphrase: abc
    #  </GnupgKeyParms>
    #
    # If <i>pubkey</i> and <i>seckey</i> are both set to <tt>nil</tt>,
    # it stores the generated key pair into your key ring.
    def generate_key(parms, pubkey = Data.new, seckey = Data.new)
      err = GPGME::gpgme_op_genkey(self, parms, pubkey, seckey)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias genkey generate_key

    # Extract the public keys of the recipients.
    def export_keys(recipients, keydata = Data.new)
      err = GPGME::gpgme_op_export(self, recipients, 0, keydata)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      keydata
    end
    alias export export_keys

    # Add the keys in the data buffer to the key ring.
    def import_keys(keydata)
      err = GPGME::gpgme_op_import(self, keydata)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias import import_keys

    def import_result
      GPGME::gpgme_op_import_result(self)
    end

    # Delete the key from the key ring.
    # If allow_secret is false, only public keys are deleted,
    # otherwise secret keys are deleted as well.
    def delete_key(key, allow_secret = false)
      err = GPGME::gpgme_op_delete(self, key, allow_secret ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias delete delete_key

    # Edit attributes of the key in the local key ring.
    def edit_key(key, editfunc, hook_value = nil, out = Data.new)
      err = GPGME::gpgme_op_edit(self, key, editfunc, hook_value, out)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias edit edit_key

    # Edit attributes of the key on the card.
    def edit_card_key(key, editfunc, hook_value = nil, out = Data.new)
      err = GPGME::gpgme_op_card_edit(self, key, editfunc, hook_value, out)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias edit_card edit_card_key
    alias card_edit edit_card_key

    # Decrypt the ciphertext and return the plaintext.
    def decrypt(cipher, plain = Data.new)
      err = GPGME::gpgme_op_decrypt(self, cipher, plain)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      plain
    end

    def decrypt_verify(cipher, plain = Data.new)
      err = GPGME::gpgme_op_decrypt_verify(self, cipher, plain)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      plain
    end

    def decrypt_result
      GPGME::gpgme_op_decrypt_result(self)
    end

    # Verify that the signature in the data object is a valid signature.
    def verify(sig, signed_text = nil, plain = Data.new)
      err = GPGME::gpgme_op_verify(self, sig, signed_text, plain)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      plain
    end

    def verify_result
      GPGME::gpgme_op_verify_result(self)
    end

    # Decrypt the ciphertext and return the plaintext.
    def decrypt_verify(cipher, plain = Data.new)
      err = GPGME::gpgme_op_decrypt_verify(self, cipher, plain)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      plain
    end

    # Remove the list of signers from this object.
    def clear_signers
      GPGME::gpgme_signers_clear(self)
    end

    # Add _keys_ to the list of signers.
    def add_signer(*keys)
      keys.each do |key|
        err = GPGME::gpgme_signers_add(self, key)
        exc = GPGME::error_to_exception(err)
        raise exc if exc
      end
    end

    # Create a signature for the text.
    # <i>plain</i> is a data object which contains the text.
    # <i>sig</i> is a data object where the generated signature is stored.
    def sign(plain, sig = Data.new, mode = GPGME::SIG_MODE_NORMAL)
      err = GPGME::gpgme_op_sign(self, plain, sig, mode)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      sig
    end

    def sign_result
      GPGME::gpgme_op_sign_result(self)
    end

    # Encrypt the plaintext in the data object for the recipients and
    # return the ciphertext.
    def encrypt(recp, plain, cipher = Data.new, flags = 0)
      err = GPGME::gpgme_op_encrypt(self, recp, flags, plain, cipher)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      cipher
    end

    def encrypt_result
      GPGME::gpgme_op_encrypt_result(self)
    end

    def encrypt_sign(recp, plain, cipher = Data.new, flags = 0)
      err = GPGME::gpgme_op_encrypt_sign(self, recp, flags, plain, cipher)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      cipher
    end
  end

  # A public or secret key.
  class Key
    private_class_method :new

    attr_reader :keylist_mode, :protocol, :owner_trust
    attr_reader :issuer_serial, :issuer_name, :chain_id
    attr_reader :subkeys, :uids

    def trust
      return :revoked if @revoked == 1
      return :expired if @expired == 1
      return :disabled if @disabled == 1
      return :invalid if @invalid == 1
    end

    def capability
      caps = Array.new
      caps << :encrypt if @can_encrypt
      caps << :sign if @can_sign
      caps << :certify if @can_certify
      caps << :authenticate if @can_authenticate
      caps
    end

    def usable_for?(purposes)
      unless purposes.kind_of? Array
        purposes = [purposes]
      end
      return false if [:revoked, :expired, :disabled, :invalid].include? trust
      return (purposes - capability).empty?
    end

    def secret?
      @secret == 1
    end

    def inspect
      primary_subkey = subkeys[0]
      sprintf("#<#{self.class} %s %4d%c/%s %s trust=%s, owner_trust=%s, \
capability=%s, subkeys=%s, uids=%s>",
              primary_subkey.secret? ? 'sec' : 'pub',
              primary_subkey.length,
              primary_subkey.pubkey_algo_letter,
              primary_subkey.fingerprint[-8 .. -1],
              primary_subkey.timestamp.strftime('%Y-%m-%d'),
              trust.inspect,
              VALIDITY_NAMES[@owner_trust].inspect,
              capability.inspect,
              subkeys.inspect,
              uids.inspect)
    end

    def to_s
      primary_subkey = subkeys[0]
      s = sprintf("%s   %4d%c/%s %s\n",
                  primary_subkey.secret? ? 'sec' : 'pub',
                  primary_subkey.length,
                  primary_subkey.pubkey_algo_letter,
                  primary_subkey.fingerprint[-8 .. -1],
                  primary_subkey.timestamp.strftime('%Y-%m-%d'))
      uids.each do |user_id|
        s << "uid\t\t#{user_id.name} <#{user_id.email}>\n"
      end
      subkeys.each do |subkey|
        s << subkey.to_s
      end
      s
    end
  end

  class SubKey
    private_class_method :new

    attr_reader :pubkey_algo, :length, :keyid, :fpr
    alias fingerprint fpr

    def trust
      return :revoked if @revoked == 1
      return :expired if @expired == 1
      return :disabled if @disabled == 1
      return :invalid if @invalid == 1
    end

    def capability
      caps = Array.new
      caps << :encrypt if @can_encrypt
      caps << :sign if @can_sign
      caps << :certify if @can_certify
      caps << :authenticate if @can_authenticate
      caps
    end

    def usable_for?(purposes)
      unless purposes.kind_of? Array
        purposes = [purposes]
      end
      return false if [:revoked, :expired, :disabled, :invalid].include? trust
      return (purposes - capability).empty?
    end

    def secret?
      @secret == 1
    end

    def timestamp
      Time.at(@timestamp)
    end

    def expires
      Time.at(@expires)
    end

    PUBKEY_ALGO_LETTERS = {
      PK_RSA => ?R,
      PK_ELG_E => ?g,
      PK_ELG => ?G,
      PK_DSA => ?D
    }

    def pubkey_algo_letter
      PUBKEY_ALGO_LETTERS[@pubkey_algo] || ??
    end

    def inspect
      sprintf("#<#{self.class} %s %4d%c/%s %s trust=%s, capability=%s>",
              secret? ? 'ssc' : 'sub',
              length,
              pubkey_algo_letter,
              (@fingerprint || @keyid)[-8 .. -1],
              timestamp.strftime('%Y-%m-%d'),
              trust.inspect,
              capability.inspect)
    end

    def to_s
      sprintf("%s   %4d%c/%s %s\n",
              secret? ? 'ssc' : 'sub',
              length,
              pubkey_algo_letter,
              (@fingerprint || @keyid)[-8 .. -1],
              timestamp.strftime('%Y-%m-%d'))
    end
  end

  class UserID
    private_class_method :new

    attr_reader :validity, :uid, :name, :comment, :email, :signatures

    def revoked?
      @revoked == 1
    end

    def invalid?
      @invalid == 1
    end

    def inspect
      "#<#{self.class} #{name} <#{email}> \
validity=#{VALIDITY_NAMES[validity]}, signatures=#{signatures.inspect}>"
    end
  end

  class KeySig
    private_class_method :new

    attr_reader :pubkey_algo, :keyid

    def revoked?
      @revoked == 1
    end

    def expired?
      @expired == 1
    end

    def invalid?
      @invalid == 1
    end

    def exportable?
      @exportable == 1
    end

    def timestamp
      Time.at(@timestamp)
    end

    def expires
      Time.at(@expires)
    end

    def inspect
      "#<#{self.class} #{keyid} timestamp=#{timestamp}, expires=#{expires}>"
    end
  end

  class VerifyResult
    private_class_method :new

    attr_reader :signatures
  end

  class Signature
    private_class_method :new

    attr_reader :summary, :fpr, :status, :notations, :wrong_key_usage
    attr_reader :validity, :validity_reason
    attr_reader :pka_trust, :pka_address
    alias fingerprint fpr

    def timestamp
      Time.at(@timestamp)
    end

    def exp_timestamp
      Time.at(@exp_timestamp)
    end

    def to_s
      ctx = Ctx.new
      if from_key = ctx.get_key(fingerprint)
        from = "#{from_key.subkeys[0].keyid} #{from_key.uids[0].uid}"
      else
        from = fingerprint
      end
      case GPGME::gpgme_err_code(status)
      when GPGME::GPG_ERR_NO_ERROR
	"Good signature from #{from}"
      when GPGME::GPG_ERR_SIG_EXPIRED
	"Expired signature from #{from}"
      when GPGME::GPG_ERR_KEY_EXPIRED
	"Signature made from expired key #{from}"
      when GPGME::GPG_ERR_CERT_REVOKED
	"Signature made from revoked key #{from}"
      when GPGME::GPG_ERR_BAD_SIGNATURE
	"Bad signature from #{from}"
      when GPGME::GPG_ERR_NO_ERROR
	"No public key for #{from}"
      end
    end
  end

  class DecryptResult
    private_class_method :new

    attr_reader :unsupported_algorithm, :wrong_key_usage
  end

  class SignResult
    private_class_method :new

    attr_reader :invalid_signers, :signatures
  end

  class EncryptResult
    private_class_method :new

    attr_reader :invalid_recipients
  end

  class InvalidKey
    private_class_method :new

    attr_reader :fpr, :reason
    alias fingerprint fpr
  end

  class NewSignature
    private_class_method :new

    attr_reader :type, :pubkey_algo, :hash_algo, :sig_class, :fpr
    alias fingerprint fpr

    def timestamp
      Time.at(@timestamp)
    end
  end

  class ImportStatus
    private_class_method :new

    attr_reader :fpr, :result, :status
    alias fingerprint fpr
  end

  class ImportResult
    private_class_method :new

    attr_reader :considered, :no_user_id, :imported, :imported_rsa, :unchanged
    attr_reader :new_user_ids, :new_sub_keys, :new_signatures, :new_revocations
    attr_reader :secret_read, :secret_imported, :secret_unchanged
    attr_reader :not_imported, :imports
  end
end
