# gpgme.rb -- OO interface to GPGME
# Copyright (C) 2003,2006 Daiki Ueno

# This file is a part of Ruby-GPGME.

# This program is free software; you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation; either version 2, or (at your option)  
# any later version.                                                   

# This program is distributed in the hope that it will be useful,      
# but WITHOUT ANY WARRANTY; without even the implied warranty of       
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the        
# GNU General Public License for more details.                         

# You should have received a copy of the GNU General Public License    
# along with GNU Emacs; see the file COPYING.  If not, write to the    
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.
 
require 'gpgme_n'

module GPGME
  PROTOCOL_NAMES = {
    GPGME_PROTOCOL_OpenPGP => "OpenPGP",
    GPGME_PROTOCOL_CMS => "CMS"
  }

  KEYLIST_MODE_NAMES = {
    GPGME_KEYLIST_MODE_LOCAL => "LOCAL",
    GPGME_KEYLIST_MODE_EXTERN => "EXTERN",
    GPGME_KEYLIST_MODE_SIGS => "SIGS",
    GPGME_KEYLIST_MODE_VALIDATE => "VALIDATE"
  }

  VALIDITY_NAMES = {
    GPGME_VALIDITY_UNKNOWN => "UNKNOWN",
    GPGME_VALIDITY_UNDEFINED => "UNDEFINED",
    GPGME_VALIDITY_NEVER => "NEVER",
    GPGME_VALIDITY_MARGINAL => "MARGINAL",
    GPGME_VALIDITY_FULL => "FULL",
    GPGME_VALIDITY_ULTIMATE => "ULTIMATE"
  }

  class Error < StandardError
    def initialize(error)
      @error = error
    end
    attr_reader :error

    def code
      GPGME::gpgme_err_code(@error)
    end

    def source
      GPGME::gpgme_err_source(@error)
    end

    def message
      GPGME::gpgme_strerror(@error)
    end

    class General < self; end
    class InvalidValue < self; end
    class UnusablePublicKey < self; end
    class UnusableSecretKey < self; end
    class NoData < self; end
    class Conflict < self; end
    class NotImplemented < self; end
    class DecryptFailed < self; end
    class BadPassphrase < self; end
    class Canceled < self; end
    class InvalidEngine < self; end
    class AmbiguousName < self; end
    class WrongKeyUsage < self; end
    class CertificateRevoked < self; end
    class CertificateExpired < self; end
    class NoCRLKnown < self; end
    class NoPolicyMatch < self; end
    class NoSecretKey < self; end
    class MissingCertificate < self; end
    class BadCertificateChain < self; end
    class UnsupportedAlgorithm < self; end
    class BadSignature < self; end
    class NoPublicKey < self; end
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

  def engine_info
    rinfo = Array.new
    GPGME::gpgme_get_engine_info(rinfo)
    rinfo
  end
  module_function :engine_info

  # A class for managing data buffers.
  class Data
    BLOCK_SIZE = 4096

    # Create a new instance.
    def self.new
      rdh = Array.new
      err = GPGME::gpgme_data_new(rdh)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance with internal buffer.
    def self.new_from_mem(buf, copy = false)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_mem(rdh, buf, buf.length, copy ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance from the specified file.
    def self.new_from_file(filename, copy = false)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_file(rdh, filename, copy ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance from the specified file descriptor.
    def self.new_from_fd(fd)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_fd(rdh, fd)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance from the specified callbacks.
    def self.new_from_cbs(cbs, hook_value = nil)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_cbs(rdh, cbs, hook_value)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Read at most _length_ bytes from the data object, or to the end
    # of file if _length_ is omitted or is +nil+.
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

    # Set the data pointer to the beginning.
    def rewind
      seek(0)
    end

    # Seek to a given _offset_ in the data object according to the
    # value of _whence_.
    def seek(offset, whence = IO::SEEK_SET)
      GPGME::gpgme_data_seek(self, offset, IO::SEEK_SET)
    end

    # Write _length_ bytes from _buffer_ into the data object.
    def write(buffer, length = buffer.length)
      GPGME::gpgme_data_write(self, buffer, length)
    end

    # Return the encoding of the underlying data.
    def encoding
      GPGME::gpgme_data_get_encoding(self)
    end

    # Set the encoding to a given _encoding_ of the underlying data object.
    def encoding=(encoding)
      err = GPGME::gpgme_data_set_encoding(self, encoding)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      encoding
    end
  end

  class EngineInfo
    private_class_method :new
    
    attr_reader :protocol, :file_name, :version, :req_version
    alias required_version req_version
  end

  # A context within which all cryptographic operations are performed.
  class Ctx
    # Create a new instance from the given _attributes_.
    # _attributes_ is a +Hash+
    #
    # * <tt>:protocol</tt> Either <tt>GPGME_PROTOCOL_OpenPGP</tt> or
    # <tt>GPGME_PROTOCOL_CMS</tt>.
    #
    # * <tt>:armor</tt>  If +true+, the output should be ASCII armored.
    #
    # * <tt>:textmode</tt> If +true+, inform the recipient that the
    # input is text.
    #
    # * <tt>:keylist_mode</tt> Either
    # <tt>GPGME_KEYLIST_MODE_LOCAL</tt>,
    # <tt>GPGME_KEYLIST_MODE_EXTERN</tt>,
    # <tt>GPGME_KEYLIST_MODE_SIGS</tt>,
    # <tt>GPGME_KEYLIST_MODE_VALIDATE</tt>.
    def self.new(attributes = Hash.new)
      rctx = Array.new
      err = GPGME::gpgme_new(rctx)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      ctx = rctx[0]
      attributes.each_pair do |key, value|
        case key
        when :protocol
          ctx.protocol = value
        when :armor
          ctx.armor = value
        when :textmode
          ctx.textmode = value
        when :keylist_mode
          ctx.keylist_mode = value
        end
      end
      ctx
    end

    # Set the _protocol_ used within this context.
    def protocol=(proto)
      err = GPGME::gpgme_set_protocol(self, proto)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      proto
    end

    # Return the _protocol_ used within this context.
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

    def inspect                 # :nodoc:
      "#<#{self.class} protocol=#{PROTOCOL_NAMES[protocol] || protocol}, \
armor=#{armor}, textmode=#{textmode}, \
keylist_mode=#{KEYLIST_MODE_NAMES[keylist_mode]}>"
    end

    # Set the passphrase callback with given hook value.
    # _passfunc_ should respond to +call+ with 5 arguments.
    #
    #  lambda {|hook, uid_hint, passphrase_info, prev_was_bad, fd|
    #    $stderr.write("Passphrase for #{uid_hint}: ")
    #    $stderr.flush
    #    begin
    #      system('stty -echo')
    #      io = IO.for_fd(fd, 'w')
    #      io.puts(gets.chomp)
    #      io.flush
    #    ensure
    #      system('stty echo')
    #    end
    #    puts
    #  }
    def set_passphrase_cb(passfunc, hook_value = nil)
      GPGME::gpgme_set_passphrase_cb(self, passfunc, hook_value)
    end

    # Set the progress callback with given hook value.
    # _progfunc_ should respond to +call+ with 5 arguments.
    #
    #  lambda {|hook, what, type, current, total|
    #    $stderr.write("#{what}: #{current}/#{total}\r")
    #    $stderr.flush
    #  }
    def set_progress_cb(progfunc, hook_value = nil)
      GPGME::gpgme_set_progress_cb(self, progfunc, hook_value)
    end

    # Initiate a key listing operation for given pattern.
    # If _pattern_ is +nil+, all available keys are returned.
    # If _secret_only_ is +true+, the only secret keys are returned.
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
    # If _pattern_ is +nil+, all available keys are returned.
    # If _secret_only_ is +true+, the only secret keys are returned.
    def each_keys(pattern = nil, secret_only = false, &block) # :yields: key
      keylist_start(pattern, secret_only)
      begin
	loop do
	  yield keylist_next
	end
      rescue EOFError
	# The last key in the list has already been returned.
      rescue
	keylist_end
      end
    end

    # Get the key with the _fingerprint_.
    # If _secret_ is +true+, secret key is returned.
    def get_key(fingerprint, secret = false)
      rkey = Array.new
      err = GPGME::gpgme_get_key(self, fingerprint, rkey, secret ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rkey[0]
    end

    # Generate a new key pair.
    # _parms_ is a string which looks like
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
    # If _pubkey_ and _seckey_ are both set to +nil+, it stores the
    # generated key pair into your key ring.
    def genkey(parms, pubkey = Data.new, seckey = Data.new)
      err = GPGME::gpgme_op_genkey(self, parms, pubkey, seckey)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias generate_key genkey

    def genkey_start(parms, pubkey, seckey)
      err = GPGME::gpgme_op_genkey_start(self, parms, pubkey, seckey)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias generate_key_start genkey_start

    # Extract the public keys of the recipients.
    def export(recipients)
      keydata = Data.new
      err = GPGME::gpgme_op_export(self, recipients, keydata)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      keydata
    end

    # Add the keys in the data buffer to the key ring.
    def import(keydata)
      err = GPGME::gpgme_op_import(self, keydata)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Delete the key from the key ring.
    # If allow_secret is false, only public keys are deleted,
    # otherwise secret keys are deleted as well.
    def delete(key, allow_secret = false)
      err = GPGME::gpgme_op_delete(self, key, allow_secret ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Decrypt the ciphertext and return the plaintext.
    def decrypt(cipher, plain = Data.new)
      err = GPGME::gpgme_op_decrypt(self, cipher, plain)
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
    # _plain_ is a data object which contains the text.
    # _sig_ is a data object where the generated signature is stored.
    def sign(plain, sig = Data.new, mode = GPGME::GPGME_SIG_MODE_NORMAL)
      err = GPGME::gpgme_op_sign(self, plain, sig, mode)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      sig
    end

    def sign_result
      GPGME::gpgme_sign_result(self)
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
      GPGME::gpgme_encrypt_result(self)
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

    def revoked?
      @revoked == 1
    end

    def expired?
      @expired == 1
    end

    def disabled?
      @disabled == 1
    end

    def invalid?
      @invalid == 1
    end

    def can_encrypt?
      @can_encrypt == 1
    end

    def can_sign?
      @can_sign == 1
    end

    def can_certify?
      @can_certify == 1
    end

    def can_authenticate?
      @can_authenticate == 1
    end

    def secret?
      @secret == 1
    end

    def inspect
      "#<#{self.class} #{secret? ? "SECRET" : "PUBLIC"} \
owner_trust=#{VALIDITY_NAMES[owner_trust]}, \
subkeys=#{subkeys.inspect}, uids=#{uids.inspect}>"
    end
  end

  class SubKey
    private_class_method :new

    attr_reader :pubkey_algo, :length, :keyid, :fpr
    alias fingerprint fpr

    def revoked?
      @revoked == 1
    end

    def expired?
      @expired == 1
    end

    def disabled?
      @disabled == 1
    end

    def invalid?
      @invalid == 1
    end

    def can_encrypt?
      @can_encrypt == 1
    end

    def can_sign?
      @can_sign == 1
    end

    def can_certify?
      @can_certify == 1
    end

    def can_authenticate?
      @can_authenticate == 1
    end

    def secret?
      @secret == 1
    end

    def timestamp
      Time.new(@timestamp)
    end

    def expires
      Time.new(@expires)
    end

    def inspect
      caps = Array.new
      caps << "encrypt" if can_encrypt?
      caps << "sign" if can_sign?
      caps << "certify" if can_certify?
      caps << "authentication" if can_authenticate?
      if secret?
        "#<#{self.class} SECRET #{keyid}, \
capability=#{caps.inspect}>"
      else
        "#<#{self.class} PUBLIC \
#{GPGME::gpgme_pubkey_algo_name(pubkey_algo)} #{keyid}, 
capability=#{caps.inspect}>"
      end
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

    attr_reader :summary, :fpr, :status, :notations
    alias fingerprint fpr

    def timestamp
      Time.at(@timestamp)
    end

    def exp_timestamp
      Time.at(@exp_timestamp)
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

module GPGME
  GpgmeError = Error
  GpgmeData = Data
  GpgmeEngineInfo = EngineInfo
  GpgmeCtx = Ctx
  GpgmeKey = Key
  GpgmeSubKey = SubKey
  GpgmeUserID = UserID
  GpgmeKeySig = KeySig
  GpgmeVerifyResult = VerifyResult
  GpgmeSignature = Signature
  GpgmeDecryptResult = DecryptResult
  GpgmeSignResult = SignResult
  GpgmeEncryptResult = EncryptResult
  GpgmeInvalidKey = InvalidKey
  GpgmeNewSignature = NewSignature
  GpgmeImportStatus = ImportStatus
  GpgmeImportResult = ImportResult

  # Deprecated functions.
  alias gpgme_trust_item_release gpgme_trust_item_unref

  def gpgme_data_rewind(dh)
    begin
      GPGME::gpgme_data_seek(dh, 0, IO::SEEK_SET)
    rescue SystemCallError => e
      return e.errno
    end
  end
  module_function :gpgme_data_rewind

  def gpgme_op_import_ext(ctx, keydata, nr)
    err = GPGME::gpgme_op_import(ctx, keydata)
    if GPGME::gpgme_err_code(err) == GPGME::GPG_ERR_NO_ERROR
      result = GPGME::gpgme_op_import_result(ctx)
      nr.push(result.considered)
    end
  end
  module_function :gpgme_op_import_ext
end
