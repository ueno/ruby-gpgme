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

  def compact_heap
    skip "GC compaction not supported" unless GC.respond_to?(:verify_compaction_references)
    begin
      GC.verify_compaction_references(expand_heap: true, toward: :empty)
    rescue ArgumentError
      GC.verify_compaction_references(toward: :empty)
    end
  rescue NotImplementedError
    skip "GC compaction not supported"
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

  describe :gpgme_data_new_from_mem do
    it "raises TypeError when the buffer is not a String" do
      assert_raises(TypeError) { GPGME::gpgme_data_new_from_mem([], 123, 3) }
    end
  end

  describe "callback getters" do
    it "return nil when no callback was set" do
      ctx = GPGME::Ctx.new
      %w[passphrase progress status].each do |name|
        getter = "gpgme_get_#{name}_cb"
        next unless GPGME.respond_to?(getter)
        func, hook = [], []
        GPGME.send(getter, ctx, func, hook)
        assert_nil func.first
        assert_nil hook.first
      end
      ctx.release
    end
  end

  describe "GC.compact" do
    it "does not move objects that libgpgme points to" do
      input = GPGME::Data.from_io(StringIO.new("Hello, compaction"))
      output = GPGME::Data.new
      GPGME::Ctx.new(armor: true) do |ctx|
        ctx.set_progress_callback(proc {})
        compact_heap
        ctx.sign(input, output, GPGME::SIG_MODE_CLEAR)
      end

      output.seek(0)
      assert_match(/Hello, compaction/, output.read)
    end
  end

  describe "asynchronous operations" do
    it "keep their data objects alive until the operation finishes" do
      ctx = GPGME::Ctx.new
      err = GPGME::gpgme_op_export_start(ctx, KEYS.first[:sha], 0,
                                         GPGME::Data.new)
      assert_nil GPGME::error_to_exception(err)
      GC.start

      ret = GPGME::gpgme_wait(ctx, [], 1)
      assert_same ctx, ret
      ctx.release
    end

    it "keep the running operation's data when another start fails" do
      ctx = GPGME::Ctx.new
      err = GPGME::gpgme_op_export_start(ctx, KEYS.first[:sha], 0,
                                         GPGME::Data.new)
      assert_nil GPGME::error_to_exception(err)
      assert_raises(TypeError) do
        GPGME::gpgme_op_export_start(ctx, nil, 0, GPGME::Data.new)
      end
      GC.start

      ret = GPGME::gpgme_wait(ctx, [], 1)
      assert_same ctx, ret
      ctx.release
    end
  end

  describe :gpgme_wait do
    it "returns the existing Ctx object when waiting on any context" do
      # libgpgme's gpgme_wait(NULL, ...) dereferences NULL if any fd is
      # ready, so the operation must have no fds left before this test
      # calls it.  A write callback that returns 0 makes libgpgme fail
      # the operation, close all its fds and mark it done, all within
      # the wait call that ran the callback.
      written = false
      callbacks = Object.new
      callbacks.define_singleton_method(:write) do |_hook, _buffer, _length|
        written = true
        0
      end
      ctx = GPGME::Ctx.new
      err = GPGME::gpgme_op_export_start(ctx, KEYS.first[:sha], 0,
                                         GPGME::Data.from_callbacks(callbacks))
      assert_nil GPGME::error_to_exception(err)

      # Run the I/O by waiting on an idle context.
      idle = GPGME::Ctx.new
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 60
      until written
        if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          idle.release
          ctx.release
          flunk "the export never wrote its output"
        end
        GPGME::gpgme_wait(idle, [], 0)
        sleep 0.01
      end
      idle.release

      status = []
      ret = GPGME::gpgme_wait(nil, status, 0)
      assert_same ctx, ret
      refute_nil GPGME::error_to_exception(status.first)

      ctx.release
      GC.start
    end
  end
end
