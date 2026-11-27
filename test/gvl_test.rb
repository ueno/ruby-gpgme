# -*- encoding: utf-8 -*-
require 'test_helper'
require 'stringio'

# Blocking libgpgme calls run without the GVL.  These tests check that
# other threads keep running, that callbacks still work and raise, and
# that a context or data object can't be used by two threads at once.
describe "GVL release" do
  before do
    skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
  end

  def now
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  SLOW_GPG = File.expand_path('support/slow_gpg', __dir__)

  # Yield a context whose gpg takes 0.5 s longer for every operation.
  def with_slow_gpg
    engine = GPGME::Engine.info.find { |e| e.protocol == GPGME::PROTOCOL_OpenPGP }
    ENV['SLOW_GPG_REAL'] = engine.file_name
    GPGME::Ctx.new(always_trust: true) do |ctx|
      GPGME::gpgme_ctx_set_engine_info(ctx, GPGME::PROTOCOL_OpenPGP, SLOW_GPG,
                                       engine.home_dir)
      yield ctx
    end
  ensure
    ENV.delete('SLOW_GPG_REAL')
  end

  # Return how many times another thread ticked, every 5 ms, while the
  # block ran.  The block should take at least 0.5 s, which allows about
  # 100 ticks.  A call that holds the GVL stops the ticker for as long
  # as it runs, so it allows close to none.
  def ticks_during
    # GC.stress makes every allocation hold the GVL for a full GC.
    skip "timing is meaningless under GC.stress" if GC.stress
    ticks = 0
    done = false
    ticker = Thread.new do
      until done
        sleep 0.005
        ticks += 1
      end
    end
    sleep 0.02
    start_ticks = ticks
    start = now
    yield
    elapsed = now - start
    count = ticks - start_ticks
    done = true
    ticker.join
    assert_operator elapsed, :>=, 0.5, "the slow gpg wrapper didn't run"
    count
  end

  # Return a Data object whose read callback calls the block, then
  # serves STRING.
  def callback_data(string, &block)
    callbacks = Object.new
    io = StringIO.new(string)
    callbacks.define_singleton_method(:read) do |_hook, length|
      block.call
      io.read(length)
    end
    callbacks.define_singleton_method(:seek) do |_hook, offset, whence|
      io.seek(offset, whence)
      io.pos
    end
    GPGME::Data.from_callbacks(callbacks)
  end

  it "lets other threads run during encrypt and sign" do
    keys = GPGME::Key.find(:public, KEYS.first[:sha])
    with_slow_gpg do |ctx|
      ticks = ticks_during do
        ctx.encrypt_sign(keys, GPGME::Data.new(TEXT[:plain]), GPGME::Data.new,
                         GPGME::ENCRYPT_ALWAYS_TRUST)
      end
      assert_operator ticks, :>=, 20
    end
  end

  it "lets other threads run during decrypt" do
    crypto = GPGME::Crypto.new(always_trust: true)
    cipher = crypto.encrypt(TEXT[:plain], recipients: KEYS.first[:sha]).to_s
    with_slow_gpg do |ctx|
      ticks = ticks_during { ctx.decrypt(GPGME::Data.new(cipher)) }
      assert_operator ticks, :>=, 20
    end
  end

  it "lets other threads run during import" do
    with_slow_gpg do |ctx|
      ticks = ticks_during do
        ctx.import_keys(GPGME::Data.new(KEYS.first[:public]))
      end
      assert_operator ticks, :>=, 20
    end
  end

  it "runs operations from many threads at once" do
    thread_safe = GPGME.thread_safe?
    GPGME.thread_safe = false
    begin
      threads = 4.times.map do |i|
        Thread.new do
          crypto = GPGME::Crypto.new(always_trust: true)
          5.times.map do |j|
            text = "message #{i}-#{j}"
            cipher = crypto.encrypt(text, recipients: KEYS.first[:sha],
                                    sign: true).to_s
            crypto.decrypt(cipher).to_s == text
          end
        end
      end
      assert_equal [true] * 20, threads.flat_map(&:value)
    ensure
      GPGME.thread_safe = thread_safe
    end
  end

  it "keeps working while another thread compacts the heap" do
    skip unless GC.respond_to?(:compact)
    done = false
    compactor = Thread.new do
      until done
        GC.compact
        sleep 0.001
      end
    end
    begin
      crypto = GPGME::Crypto.new(always_trust: true)
      10.times do |i|
        text = "message #{i}"
        cipher = crypto.encrypt(callback_data(text) { GC.start },
                                recipients: [KEYS.first[:sha]],
                                sign: true).to_s
        assert_equal text, crypto.decrypt(cipher).to_s
      end
    ensure
      done = true
      compactor.join
    end
  end

  it "raises an exception from a read callback" do
    data = callback_data(TEXT[:plain]) { raise ArgumentError, "read failed" }
    crypto = GPGME::Crypto.new(always_trust: true)
    error = assert_raises(ArgumentError) do
      crypto.encrypt(data, recipients: KEYS.first[:sha])
    end
    assert_equal "read failed", error.message
  end

  it "raises an exception from a status callback" do
    calls = 0
    callback = lambda do |_hook, _keyword, _args|
      calls += 1
      raise IOError, "status failed"
    end
    keys = GPGME::Key.find(:public, KEYS.first[:sha])
    GPGME::Ctx.new(always_trust: true, status_callback: callback) do |ctx|
      # Send every status line to the callback.
      GPGME::gpgme_set_ctx_flag(ctx, "full-status", "1")
      error = assert_raises(IOError) do
        ctx.encrypt(keys, GPGME::Data.new(TEXT[:plain]), GPGME::Data.new,
                    GPGME::ENCRYPT_ALWAYS_TRUST)
      end
      assert_equal "status failed", error.message
      # No Ruby code runs after the first exception.
      assert_equal 1, calls
    end
  end

  it "supports throw from a callback" do
    data = callback_data(TEXT[:plain]) { throw :stop, :thrown }
    crypto = GPGME::Crypto.new(always_trust: true)
    result = catch(:stop) do
      crypto.encrypt(data, recipients: KEYS.first[:sha])
      :not_thrown
    end
    assert_equal :thrown, result
  end

  it "can use the context again after a callback raises" do
    GPGME::Ctx.new(always_trust: true) do |ctx|
      keys = ctx.keys(KEYS.first[:sha])
      data = callback_data(TEXT[:plain]) { raise "boom" }
      assert_raises(RuntimeError) do
        ctx.encrypt(keys, data, GPGME::Data.new, GPGME::ENCRYPT_ALWAYS_TRUST)
      end
      output = GPGME::Data.new
      ctx.encrypt(keys, GPGME::Data.new(TEXT[:plain]), output,
                  GPGME::ENCRYPT_ALWAYS_TRUST)
      refute_empty output.to_s
    end
  end

  it "reads data from a Ruby IO" do
    crypto = GPGME::Crypto.new(always_trust: true)
    cipher = crypto.encrypt(StringIO.new(TEXT[:plain]),
                            recipients: KEYS.first[:sha]).to_s
    output = StringIO.new
    crypto.decrypt(GPGME::Data.new(cipher), output: output)
    assert_equal TEXT[:plain], output.string
  end

  it "runs a nested operation from a callback" do
    crypto = GPGME::Crypto.new(always_trust: true)
    found = nil
    data = callback_data(TEXT[:plain]) do
      found ||= GPGME::Key.find(:public, KEYS.last[:sha]).first
    end
    cipher = crypto.encrypt(data, recipients: KEYS.first[:sha]).to_s
    assert_equal KEYS.last[:sha], found.email
    assert_equal TEXT[:plain], crypto.decrypt(cipher).to_s
  end

  it "runs callbacks that switch fibers in the middle of a call" do
    # GPGME.thread_safe would make the second fiber wait for the first.
    thread_safe = GPGME.thread_safe?
    GPGME.thread_safe = false
    begin
      crypto = GPGME::Crypto.new(always_trust: true)
      encrypt_in_fiber = lambda do |text|
        paused = false
        data = callback_data(text) do
          unless paused
            paused = true
            Fiber.yield
          end
        end
        Fiber.new { crypto.encrypt(data, recipients: KEYS.first[:sha]).to_s }
      end

      first = encrypt_in_fiber.call("first")
      second = encrypt_in_fiber.call("second")
      first.resume    # pauses inside its read callback
      second.resume   # starts while the first call is paused
      first_cipher = first.resume
      second_cipher = second.resume
      assert_equal "first", crypto.decrypt(first_cipher).to_s
      assert_equal "second", crypto.decrypt(second_cipher).to_s

      # The first call is gone, so a callback called straight from Ruby
      # must not find it.
      data = callback_data("x") { raise IOError, "direct" }
      assert_raises(IOError) { data.read(1) }
    ensure
      GPGME.thread_safe = thread_safe
    end
  end

  it "frees the context when Thread#raise interrupts a call" do
    stop = Class.new(StandardError)
    GPGME::Ctx.new do |ctx|
      started = Queue.new
      thread = Thread.new do
        started << true
        loop { ctx.get_key(KEYS.first[:sha]) }
      end
      # The thread is meant to die from the exception below.
      thread.report_on_exception = false
      started.pop
      sleep 0.05
      thread.raise(stop)
      assert_raises(stop) { thread.join }
      # The interrupted call no longer marks the context busy.
      assert_equal KEYS.first[:sha], ctx.get_key(KEYS.first[:sha]).email
    end
  end

  describe "an object in use" do
    # Start an encryption on another thread, and yield while its read
    # callback waits.
    def while_encrypting(ctx, input)
      entered = Queue.new
      release = Queue.new
      data = callback_data(TEXT[:plain]) do
        entered << true
        release.pop
      end
      keys = ctx.keys(KEYS.first[:sha])
      thread = Thread.new do
        ctx.encrypt(keys, input || data, GPGME::Data.new,
                    GPGME::ENCRYPT_ALWAYS_TRUST)
      end
      entered.pop
      begin
        yield data
      ensure
        # Let every later read go through until the thread finishes.
        release << true until thread.join(0.01)
      end
    end

    it "can't be used by another thread" do
      GPGME::Ctx.new(always_trust: true) do |ctx|
        while_encrypting(ctx, nil) do |data|
          error = assert_raises(ThreadError) { ctx.armor = true }
          assert_match(/GPGME::Ctx is in use/, error.message)
          assert_raises(ThreadError) { ctx.keys(KEYS.first[:sha]) }
          assert_raises(ThreadError) { data.read }
          assert_raises(ThreadError) { ctx.release }
        end
        # The context is free again once the operation ends.
        assert_equal 1, ctx.keys(KEYS.first[:sha]).size
      end
    end

    it "can't be released by a callback" do
      ctx = GPGME::Ctx.new(always_trust: true)
      keys = ctx.keys(KEYS.first[:sha])
      data = callback_data(TEXT[:plain]) { ctx.release }
      error = assert_raises(ThreadError) do
        ctx.encrypt(keys, data, GPGME::Data.new, GPGME::ENCRYPT_ALWAYS_TRUST)
      end
      assert_match(/in use/, error.message)
      ctx.release
    end
  end
end
