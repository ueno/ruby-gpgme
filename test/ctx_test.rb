# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::Ctx do
  before do
    skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
  end

  it "can instantiate" do
    assert_instance_of GPGME::Ctx, GPGME::Ctx.new
  end

  it "doesn't close itself" do
    GPGME.expects(:gpgme_release).never
    GPGME::Ctx.new
  end

  it "closes itself if called with a block" do
    GPGME.expects(:gpgme_release).with(anything)
    GPGME::Ctx.new { |ctx| }
  end

  it "can be closed with the release method" do
    GPGME.expects(:gpgme_release).with(anything)
    ctx = GPGME::Ctx.new
    ctx.release
  end

  describe :new do
    before do
      info = GPGME::Engine.info.first
      skip if /\A2\.[01]|\A1\./ === info.version
    end

    # We consider :armor, :protocol, :textmode and :keylist_mode as tested
    # with the other tests of this file. Here we test the rest

    it ":password sets the password for the key" do
      with_key PASSWORD_KEY do
        input  = GPGME::Data.new(TEXT[:passwored])
        output = GPGME::Data.new

        GPGME::Ctx.new(:password => 'gpgme') do |ctx|
          ctx.decrypt_verify input, output

          output.seek 0
          assert_equal "Hi there", output.read.chomp

          recipients = ctx.decrypt_result.recipients
          assert_equal 1, recipients.size

          recipient_key = ctx.get_key(recipients.first.keyid)
          key = ctx.get_key(PASSWORD_KEY[:sha])

          assert_equal recipient_key, key
        end
      end
    end
  end

  describe :decrypt_result do
    it "returns the list of encyption recipients" do
      cipher = GPGME::Data.new(KEY_1_ENCRYPTED)
      output = GPGME::Data.new

      GPGME::Ctx.new do |ctx|
        ctx.decrypt_verify(cipher, output)
        assert_equal 1, ctx.decrypt_result.recipients.size
      end
    end

    it "should not segfault" do
      cipher = GPGME::Data.new(KEY_1_ENCRYPTED)
      ouput = GPGME::Data.new
      
      GPGME::Ctx.new do |ctx|
        assert_raises ArgumentError do
          ctx.decrypt_result
        end
      end
    end
  end

  describe :armor do
    it "sets false by default" do
      ctx = GPGME::Ctx.new
      refute ctx.armor
    end

    it "can set" do
      ctx = GPGME::Ctx.new
      ctx.armor = true
      assert ctx.armor
    end

    it "can set and get armor" do
      ctx = GPGME::Ctx.new(:armor => false)
      refute ctx.armor
      ctx = GPGME::Ctx.new(:armor => true)
      assert ctx.armor
    end
  end

  describe :protocol do
    it "sets 0 by default" do
      ctx = GPGME::Ctx.new
      assert_equal 0, ctx.protocol
    end

    it "can set" do
      ctx = GPGME::Ctx.new
      ctx.protocol = 1
      assert_equal 1, ctx.protocol
    end

    it "can set and get protocol" do
      ctx = GPGME::Ctx.new(:protocol => GPGME::PROTOCOL_OpenPGP)
      assert_equal GPGME::PROTOCOL_OpenPGP, ctx.protocol
    end

    it "doesn't allow just any value" do
      assert_raises GPGME::Error::InvalidValue do
        ctx = GPGME::Ctx.new(:protocol => -200)
      end
    end
  end

  describe :textmode do
    it "sets false by default" do
      ctx = GPGME::Ctx.new
      refute ctx.textmode
    end

    it "can set" do
      ctx = GPGME::Ctx.new
      ctx.textmode = true
      assert ctx.textmode
    end

    it "can set and get textmode" do
      ctx = GPGME::Ctx.new(:textmode => false)
      refute ctx.textmode
      ctx = GPGME::Ctx.new(:textmode => true)
      assert ctx.textmode
    end
  end

  describe :keylist_mode do
    it "sets local by default" do
      ctx = GPGME::Ctx.new
      assert_equal GPGME::KEYLIST_MODE_LOCAL, ctx.keylist_mode
    end

    it "can set and get" do
      ctx = GPGME::Ctx.new(:keylist_mode => GPGME::KEYLIST_MODE_SIGS)
      assert_equal GPGME::KEYLIST_MODE_SIGS, ctx.keylist_mode
    end

    it "can set" do
      ctx = GPGME::Ctx.new
      ctx.keylist_mode = GPGME::KEYLIST_MODE_SIGS
      assert_equal GPGME::KEYLIST_MODE_SIGS, ctx.keylist_mode
    end

    it "allows the four possible values" do
      [GPGME::KEYLIST_MODE_LOCAL, GPGME::KEYLIST_MODE_EXTERN,
      GPGME::KEYLIST_MODE_SIGS, GPGME::KEYLIST_MODE_VALIDATE].each do |mode|
        GPGME::Ctx.new(:keylist_mode => mode)
      end
    end

    # It's not crashing?
    # it "crashes with other values" do
    #   GPGME::Ctx.new(:keylist_mode => -200)
    # end
  end

  # describe :set_passphrase_callback do
  #   def test_pass_func(par1,par2,par3,par4,par5)
  #     par1
  #   end

  #   test "it sets the passphrase"

  # end

  describe "keylist operations" do
    it "can return all of the keys" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys
      ctx.release

      assert keys.size >= 4
      KEYS.each do |key|
        assert keys.map(&:email).include?(key[:sha])
      end
    end

    it "can return keys filtering by a pattern" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys(KEYS.first[:sha])
      ctx.release

      assert_equal 1, keys.size
      assert_equal KEYS.first[:sha], keys.first.email
    end

    it "can return only secret keys" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys(KEYS.first[:sha], true)
      ctx.release

      assert keys.all?(&:secret?)
    end

    it "can return only public keys" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys(KEYS.first[:sha], false)
      ctx.release

      refute keys.any?(&:secret?)
    end

    it "returns only public keys by default" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys(KEYS.first[:sha])
      ctx.release

      refute keys.any?(&:secret?)
    end

    it "can iterate through them returning only public keys" do
      GPGME::Ctx.new do |ctx|
        ctx.each_key do |key|
          assert_instance_of GPGME::Key, key
          refute key.secret?
        end
      end
    end

    it "can iterate through them getting only secret ones" do
      GPGME::Ctx.new do |ctx|
        ctx.each_key("", true) do |key|
          assert_instance_of GPGME::Key, key
          assert key.secret?
        end
      end
    end

    it "can iterate through them filtering by pattern" do
      num = 0
      GPGME::Ctx.new do |ctx|
        ctx.each_key(KEYS.first[:sha]) do |key|
          assert_instance_of GPGME::Key, key
          assert_equal KEYS.first[:sha], key.email
          num += 1
        end
      end
      assert_equal 1, num
    end

    it "can get only a specific key" do
      GPGME::Ctx.new do |ctx|
        key = ctx.get_key(KEYS.first[:sha])
        assert_instance_of GPGME::Key, key
        assert_equal KEYS.first[:sha], key.email
      end
    end
  end

  describe "key generation" do
    it "generates a key according to specifications" do
      key = <<-RUBY
<GnupgKeyParms format="internal">
Key-Type: DSA
Key-Length: 1024
Subkey-Type: ELG-E
Subkey-Length: 1024
Name-Real: Key Testér
Name-Comment: with some comments
Name-Email: test_generation@example.com
Expire-Date: 0
Passphrase: wadus
</GnupgKeyParms>
RUBY

      if RUBY_VERSION > "1.9"
        assert_equal key.encoding, Encoding::UTF_8
      end

      keys_amount = GPGME::Key.find(:public).size
      GPGME::Ctx.new do |ctx|
        ctx.generate_key(key.chomp)
      end

      assert_equal keys_amount + 1, GPGME::Key.find(:public).size

      GPGME::Key.find(:public, "test_generation@example.com").each do |k|

        if RUBY_VERSION > "1.9"
          # Make sure UTF-8 in and UTF-8 out.
          assert_equal "Key Testér", k.name
          assert_equal k.name.encoding, Encoding::UTF_8
        end
        k.delete!(true)
      end
    end
  end

  describe "key export/import" do
    it "exports and imports all keys when passing an empty string" do
      original_keys = GPGME::Key.find(:public)
      export = ""
      GPGME::Ctx.new do |ctx|
        export = ctx.export_keys("")
      end
      export.seek(0)

      GPGME::Key.find(:public).each{|k| k.delete!(true)}
      assert_equal 0, GPGME::Key.find(:public).size

      result = GPGME::Key.import(export)
      current_keys = GPGME::Key.find(:public)
      assert_equal original_keys.size, current_keys.size
      assert_equal result.imports.size, current_keys.size
      assert result.imports.all?{|import| import.status == 1}

      assert_equal original_keys.map(&:sha), original_keys.map(&:sha)

      import_keys # If the test fails for some reason, it won't break others.
    end

    it "exports a minimal key if given the mode" do
      remove_all_keys
      GPGME::Key.import(KEY_WITH_SIGNATURE[:public])
      key = GPGME::Key.find(KEY_WITH_SIGNATURE[:sha]).first
      output_normal = GPGME::Data.new
      output_minimal = GPGME::Data.new
      ctx = GPGME::Ctx.new

      ctx.export_keys(key.sha, output_normal)
      ctx.export_keys(key.sha, output_minimal, 4)

      output_normal.seek(0)
      output_minimal.seek(0)

      assert_equal output_normal.read.size, 849
      assert_equal output_minimal.read.size, 668

      import_keys # If the test fails for some reason, it won't break others.
    end

    it "exports only one key" do
      original_keys = GPGME::Key.find(:public)
      key           = original_keys.first
      export = ""
      GPGME::Ctx.new do |ctx|
        export = ctx.export_keys(key.sha)
      end
      export.seek(0)

      key.delete!(true)

      result = GPGME::Key.import(export)
      assert_equal 1, result.imports.size

      import = result.imports.first

      imported_key = GPGME::Key.find(:public, import.fpr).first
      assert_equal key.sha, imported_key.sha
      assert_equal key.email, imported_key.email
      import_keys # If the test fails for some reason, it won't break others.
    end

    it "imports keys and can get a result object" do
      without_key KEYS.last do
        public_amount = GPGME::Key.find(:public).size
        secret_amount = GPGME::Key.find(:secret).size

        result = nil
        GPGME::Ctx.new do |ctx|
          ctx.import_keys(GPGME::Data.new(KEYS.last[:public]))
          ctx.import_keys(GPGME::Data.new(KEYS.last[:secret]))

          result = ctx.import_result
        end

        assert_equal secret_amount + 1, GPGME::Key.find(:secret).size
        assert_equal public_amount + 1, GPGME::Key.find(:public).size
        assert_instance_of GPGME::ImportResult, result
        assert_instance_of GPGME::ImportStatus, result.imports.first
      end
    end
  end

  describe "deleting/editing of keys" do
    it "can delete keys" do
      original_keys = GPGME::Key.find(:public)
      key = original_keys.first

      GPGME::Ctx.new do |ctx|
        ctx.delete_key key, true
      end

      assert_empty GPGME::Key.find(:public, key.sha)
      import_keys
    end

    it "raises error if there's a secret key attached but secret key deletion isn't marked" do
      original_keys = GPGME::Key.find(:public)
      key = original_keys.first

      assert_raises GPGME::Error::Conflict do
        GPGME::Ctx.new do |ctx|
          ctx.delete_key key
        end
      end
    end
  end

  # Don't know how to test or use edit_key and edit_card
end
