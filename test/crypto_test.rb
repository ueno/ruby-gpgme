# -*- encoding: utf-8 -*-
require 'test_helper'
require 'tempfile'

describe GPGME::Crypto do
  before do
    skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
  end

  describe "default options functionality" do
    it "allows operation from instances normally" do
      crypto = GPGME::Crypto.new
      encrypted = crypto.encrypt TEXT[:plain], :always_trust => true, :recipients => KEYS.first[:sha]
      assert_equal TEXT[:plain], crypto.decrypt(encrypted).read
    end

    it "can set default options when using the instance way" do
      crypto = GPGME::Crypto.new :always_trust => true
      encrypted = crypto.encrypt TEXT[:plain], :recipients => KEYS.first[:sha]
      assert_equal TEXT[:plain], crypto.decrypt(encrypted).read
    end

    it "but they can still be overwritten" do
      crypto = GPGME::Crypto.new :always_trust => false
      encrypted = crypto.encrypt TEXT[:plain], :always_trust => true, :recipients => KEYS.first[:sha]
      assert_equal TEXT[:plain], crypto.decrypt(encrypted).read
    end
  end

  describe "roundtrip encryption/decryption" do
    it "does the roundtrip encrypting" do
      crypto = GPGME::Crypto.new
      encrypted = crypto.encrypt TEXT[:plain], :always_trust => true, :recipients => KEYS.first[:sha]
      assert_equal TEXT[:plain], crypto.decrypt(encrypted).read
    end

    it "does so even with armored encrypted stuff" do
      crypto = GPGME::Crypto.new
      encrypted = crypto.encrypt TEXT[:plain], :always_trust => true, :armor => true
      assert_equal TEXT[:plain], crypto.decrypt(encrypted).read
    end
  end

  describe :encrypt do
    it "should raise an error if the recipients aren't trusted" do
      assert_raises GPGME::Error::UnusablePublicKey do
        GPGME::Crypto.new.encrypt TEXT[:plain]
      end
    end

    it "doesn't raise an error and returns something when encrypting nothing" do
      data = GPGME::Crypto.new.encrypt nil, :always_trust => true
      refute_empty data.read
      data = GPGME::Crypto.new.encrypt "", :always_trust => true
      refute_empty data.read
    end

    it "can specify which key(s) to use for encrypting with a string" do
      crypto    = GPGME::Crypto.new :always_trust => true
      key       = KEYS.last
      encrypted = crypto.encrypt TEXT[:plain], :recipients => key[:sha]
      assert_equal TEXT[:plain], crypto.decrypt(encrypted).read

      remove_key key
      encrypted.seek 0
      assert_raises GPGME::Error::NoSecretKey do
        crypto.decrypt(encrypted)
      end
      import_key key
    end

    it "can specify which key to use for encrypting with a Key object" do
      crypto    = GPGME::Crypto.new :always_trust => true
      key       = KEYS.last
      real_key  = GPGME::Key.find(:public, key[:sha]).first

      encrypted = crypto.encrypt TEXT[:plain], :recipients => real_key
      assert_equal TEXT[:plain], crypto.decrypt(encrypted).read

      remove_key key
      encrypted.seek 0
      assert_raises GPGME::Error::NoSecretKey do
        crypto.decrypt(encrypted)
      end
      import_key key
    end

    it "can also sign at the same time" do
      crypto      = GPGME::Crypto.new :always_trust => true
      encrypted   = crypto.encrypt TEXT[:plain], :sign => true
      signatures  = 0

      crypto.verify(encrypted) do |signature|
        assert_instance_of GPGME::Signature, signature
        signatures += 1
      end

      assert_equal 1, signatures
    end

    it "can be signed by more than one person" do
      crypto      = GPGME::Crypto.new :always_trust => true
      encrypted   = crypto.encrypt TEXT[:plain], :sign => true, :signers => KEYS.map{|k| k[:sha]}
      signatures  = 0

      crypto.verify(encrypted) do |signature|
        assert_instance_of GPGME::Signature, signature
        signatures += 1
      end

      assert_equal 4, signatures
    end

    it "outputs to a file if specified" do
      crypto    = GPGME::Crypto.new :always_trust => true
      file      = Tempfile.new "test"
      crypto.encrypt TEXT[:plain], :output => file
      file_contents = file.read
      file.seek 0

      refute_empty file_contents
      assert_equal TEXT[:plain], crypto.decrypt(file).read
    end

    # TODO find how to test
    # it "raises GPGME::Error::UnusablePublicKey"
    # it "raises GPGME::Error::UnusableSecretKey"
  end

  describe "symmetric encryption/decryption" do
    before do
      info = GPGME::Engine.info.first
      skip if /\A2\.[01]|\A1\./ === info.version
    end

    it "requires a password to encrypt" do
      GPGME::Crypto.new.encrypt TEXT[:plain], :symmetric => true
    end

    it "requires a password to decrypt" do
      crypto = GPGME::Crypto.new
      encrypted_data = crypto.encrypt TEXT[:plain],
        :symmetric => true, :password => "gpgme"

      crypto.decrypt encrypted_data
    end

    it "can encrypt and decrypt with the same password" do
      crypto = GPGME::Crypto.new :symmetric => true, :password => "gpgme"
      encrypted_data = crypto.encrypt TEXT[:plain]
      plain = crypto.decrypt encrypted_data

      assert_equal "Hi there", plain.read
    end
  end

  describe :decrypt do
    it "decrypts encrypted stuff" do
      assert_equal TEXT[:plain], GPGME::Crypto.new.decrypt(TEXT[:encrypted]).read
    end

    it "will not get into the signatures block if there's none" do
      GPGME::Crypto.new.decrypt(TEXT[:encrypted]) do |signature|
        flunk "If I'm here means there was some signature"
      end
      pass
    end

    it "will get signature elements if the encrypted thing was signed" do
      signatures = 0
      GPGME::Crypto.new.decrypt(TEXT[:signed]) do |signature|
        assert_instance_of GPGME::Signature, signature
        signatures += 1
      end
      assert_equal 1, signatures
    end

    it "writes to the output if passed" do
      buffer = GPGME::Data.new
      GPGME::Crypto.new.decrypt(TEXT[:encrypted], :output => buffer)
      assert_equal TEXT[:plain], buffer.read
    end

    # TODO find ways to test this
    # it "raises UnsupportedAlgorithm"
    # it "raises WrongKeyUsage"

    it "raises DecryptFailed when the decrypting key isn't available" do
      assert_raises GPGME::Error::NoSecretKey do
        GPGME::Crypto.new.decrypt(TEXT[:unavailable])
      end
    end
  end

  describe :sign do
    it "signs normal strings" do
      crypto = GPGME::Crypto.new
      signatures = 0
      sign = crypto.sign "Hi there"

      crypto.verify(sign) do |signature|
        assert_instance_of GPGME::Signature, signature
        assert signature.valid?
        signatures += 1
      end

      assert_equal 1, signatures
    end

    # TODO Find how to import an expired public key
    # it "raises an error if trying to sign with an expired key" do
    #   with_key EXPIRED_KEY do
    #     crypto  = GPGME::Crypto.new
    #     assert_raises GPGME::Error::General do
    #       sign = crypto.sign "Hi there", :signer => EXPIRED_KEY[:sha]
    #     end
    #   end
    # end

    it "selects who to sign for" do
      crypto  = GPGME::Crypto.new
      sign    = crypto.sign "Hi there", :signer => KEYS.last[:sha]
      key     = GPGME::Key.get(KEYS.last[:sha])

      signatures = 0

      crypto.verify(sign) do |signature|
        assert_instance_of GPGME::Signature, signature
        assert_equal key, signature.key
        signatures += 1
      end

      assert_equal 1, signatures
    end

  end
end
