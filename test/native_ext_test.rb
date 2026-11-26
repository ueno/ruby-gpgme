# -*- encoding: utf-8 -*-
require 'test_helper'
require 'stringio'

# Regression tests for memory-safety bugs in ext/gpgme/gpgme_n.c.
describe "GPGME native extension" do
  before do
    skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
  end

  def export_size(pattern)
    data = GPGME::Data.new
    GPGME::Ctx.new { |ctx| ctx.export_keys(pattern, data) }
    data.seek(0)
    data.read.bytesize
  end

  describe "read callback" do
    it "fails instead of overflowing when the callback returns too much" do
      callbacks = Object.new
      def callbacks.read(hook, length)
        "x" * (length * 4)
      end

      data = GPGME::Data.from_callbacks(callbacks)
      assert_raises(Errno::EINVAL) { data.read(16) }
    end
  end

  describe :gpgme_op_export_ext do
    it "exports every key in the pattern array" do
      shas = KEYS.first(3).map { |key| key[:sha] }
      expected = shas.sum { |sha| export_size(sha) }

      GPGME::Ctx.new do |ctx|
        data = GPGME::Data.new
        err = GPGME::gpgme_op_export_ext(ctx, shas, 0, data)
        assert_nil GPGME::error_to_exception(err)
        data.seek(0)
        assert_equal expected, data.read.bytesize
      end
    end
  end

  describe :gpgme_op_export_keys do
    it "exports every key in the key array" do
      skip unless GPGME.respond_to?(:gpgme_op_export_keys)
      shas = KEYS.first(3).map { |key| key[:sha] }
      expected = shas.sum { |sha| export_size(sha) }
      keys = shas.map { |sha| GPGME::Key.find(:public, sha).first }

      GPGME::Ctx.new do |ctx|
        data = GPGME::Data.new
        err = GPGME::gpgme_op_export_keys(ctx, keys, 0, data)
        assert_nil GPGME::error_to_exception(err)
        data.seek(0)
        assert_equal expected, data.read.bytesize
      end
    end
  end

  describe :gpgme_data_write do
    it "rejects a length larger than the buffer" do
      data = GPGME::Data.new
      assert_raises(ArgumentError) { data.write("ab", 4096) }
    end
  end

  describe "Data#write" do
    it "writes every byte of a multibyte string" do
      data = GPGME::Data.new
      data.write("日本語")
      data.seek(0)
      assert_equal "日本語".b, data.read
    end
  end
end
