# -*- encoding: utf-8 -*-
require 'test_helper'
require 'stringio'

describe GPGME::IOCallbacks do
  describe "encoding handling" do
    it "writes binary data to binary IO without error" do
      io = StringIO.new
      io.set_encoding(Encoding::ASCII_8BIT)
      callbacks = GPGME::IOCallbacks.new(io)

      # Binary data with bytes that aren't valid UTF-8
      binary_data = "\xC3\x28".b # Invalid UTF-8 sequence

      callbacks.write(nil, binary_data, binary_data.bytesize)
      io.rewind
      assert_equal binary_data, io.read
    end

    it "writes UTF-8 data to UTF-8 IO without error" do
      io = StringIO.new
      io.set_encoding(Encoding::UTF_8)
      callbacks = GPGME::IOCallbacks.new(io)

      utf8_data = "Héllo Wörld! 日本語"

      callbacks.write(nil, utf8_data.encode(Encoding::UTF_8), utf8_data.bytesize)
      io.rewind
      assert_equal utf8_data, io.read
    end

    it "handles encoding conversion when IO has different encoding" do
      io = StringIO.new
      io.set_encoding(Encoding::UTF_8)
      callbacks = GPGME::IOCallbacks.new(io)

      # ASCII-8BIT string with valid UTF-8 bytes
      data = "Hello World".b

      # Should not raise Encoding::UndefinedConversionError
      callbacks.write(nil, data, data.bytesize)
      io.rewind
      assert_equal "Hello World", io.read
    end

    it "replaces invalid characters when converting encodings" do
      io = StringIO.new
      io.set_encoding(Encoding::UTF_8)
      callbacks = GPGME::IOCallbacks.new(io)

      # Invalid UTF-8 sequence in ASCII-8BIT string
      invalid_data = "Hello\xC3\x28World".b

      # Should not raise, should replace invalid chars
      callbacks.write(nil, invalid_data, invalid_data.bytesize)
      io.rewind
      result = io.read
      # The invalid sequence should be replaced
      refute_nil result
      assert result.valid_encoding?
    end

    it "reads data from IO" do
      io = StringIO.new("test data")
      callbacks = GPGME::IOCallbacks.new(io)

      result = callbacks.read(nil, 9)
      assert_equal "test data", result
    end

    it "seeks in IO" do
      io = StringIO.new("test data")
      callbacks = GPGME::IOCallbacks.new(io)

      callbacks.read(nil, 4) # read "test"
      pos = callbacks.seek(nil, 0, IO::SEEK_SET)
      assert_equal 0, pos

      result = callbacks.read(nil, 4)
      assert_equal "test", result
    end

    it "returns current position for seek with offset 0 and SEEK_CUR" do
      io = StringIO.new("test data")
      callbacks = GPGME::IOCallbacks.new(io)

      callbacks.read(nil, 5) # read "test "
      pos = callbacks.seek(nil, 0, IO::SEEK_CUR)
      assert_equal 5, pos
    end
  end

  describe "integration with GPGME signing" do
    before do
      skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
    end

    it "clearsigns UTF-8 data without encoding errors" do
      utf8_text = "Héllo Wörld! Ünïcödé tëxt 日本語"

      crypto = GPGME::Crypto.new
      output = StringIO.new
      output.set_encoding(Encoding::UTF_8)

      # This should not raise Encoding::UndefinedConversionError
      crypto.sign(utf8_text, mode: GPGME::SIG_MODE_CLEAR, output: output)

      output.rewind
      result = output.read
      refute_empty result
      assert result.include?("BEGIN PGP SIGNED MESSAGE")
    end

    it "signs UTF-8 data and outputs to default buffer without errors" do
      utf8_text = "Ünïcödé tëxt: äöü ÄÖÜ ß"

      crypto = GPGME::Crypto.new
      signed = crypto.sign(utf8_text)

      result = signed.read
      refute_empty result
    end

    it "encrypts and decrypts UTF-8 data correctly" do
      utf8_text = "Sëcrét mëssägé with spëcïäl chäräctërs: 日本語"

      crypto = GPGME::Crypto.new(always_trust: true)
      encrypted = crypto.encrypt(utf8_text, recipients: KEYS.first[:sha])
      decrypted = crypto.decrypt(encrypted)

      result = decrypted.read
      # Force UTF-8 encoding since GPGME returns binary data
      result.force_encoding(Encoding::UTF_8)
      assert_equal utf8_text, result
    end
  end

  describe "default internal encoding support" do
    it "respects Encoding.default_internal when set" do
      # Save original setting
      original_internal = Encoding.default_internal
      original_verbose = $VERBOSE

      begin
        # Suppress warning about setting Encoding.default_internal
        $VERBOSE = nil
        Encoding.default_internal = Encoding::UTF_8
        $VERBOSE = original_verbose

        io = StringIO.new
        io.set_encoding(Encoding::UTF_8)
        callbacks = GPGME::IOCallbacks.new(io)

        # Valid UTF-8 data
        utf8_data = "Tëst dätä"
        callbacks.write(nil, utf8_data, utf8_data.bytesize)

        io.rewind
        result = io.read
        assert_equal utf8_data, result
      ensure
        # Restore original settings
        $VERBOSE = nil
        Encoding.default_internal = original_internal
        $VERBOSE = original_verbose
      end
    end
  end
end
