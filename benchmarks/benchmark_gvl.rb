# Measures how long blocking GPGME calls stall other Ruby threads, and
# how well operations scale across threads.
#
#   ruby benchmarks/benchmark_gvl.rb [EXT_DIR]
#
# EXT_DIR holds the gpgme_n extension to load (default: tmp).  Set
# BENCH_GNUPGHOME to reuse a home directory and skip generating the
# 4096-bit RSA key on every run.
ext_dir = File.expand_path(ARGV[0] || File.join(__dir__, '..', 'tmp'))
$LOAD_PATH.unshift(ext_dir, File.join(__dir__, '..', 'lib'))
require 'gpgme'
require 'tmpdir'

ITERATIONS = Integer(ENV.fetch('ITERATIONS', 10))
THREADS = Integer(ENV.fetch('THREADS', 4))
TICK = 0.005

home = ENV['BENCH_GNUPGHOME'] || Dir.mktmpdir
GPGME::Engine.home_dir = home

if GPGME::Key.find(:secret, 'bench@example.com').empty?
  warn "Generating a 4096-bit RSA key in #{home}..."
  GPGME::Ctx.new do |ctx|
    ctx.genkey(<<~PARMS)
      <GnupgKeyParms format="internal">
      Key-Type: RSA
      Key-Length: 4096
      Subkey-Type: RSA
      Subkey-Length: 4096
      Name-Real: Bench
      Name-Email: bench@example.com
      Expire-Date: 0
      %no-protection
      </GnupgKeyParms>
    PARMS
  end
end

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

# Run the block while a thread tries to tick every TICK seconds.
# Returns the mean time per call and the longest gap between ticks.
def with_ticker(n)
  gaps = []
  done = false
  ticker = Thread.new do
    last = now
    until done
      sleep TICK
      t = now
      gaps << t - last
      last = t
    end
  end
  sleep 0.05
  start = now
  n.times { yield }
  elapsed = now - start
  done = true
  ticker.join
  [elapsed / n, gaps.max]
end

def ms(seconds)
  format('%8.1f ms', seconds * 1000)
end

plain = 'Hello, World! ' * 1000
crypto = GPGME::Crypto.new(always_trust: true, armor: true)
key = 'bench@example.com'
cipher = crypto.encrypt(plain, recipients: key, sign: true).to_s
signature = crypto.sign(plain).to_s
exported = GPGME::Key.export(key).to_s

ops = {
  'encrypt + sign' => -> { crypto.encrypt(plain, recipients: key, sign: true) },
  'decrypt + verify' => -> { crypto.decrypt(cipher) { |_sig| } },
  'sign' => -> { crypto.sign(plain) },
  'verify' => -> { crypto.verify(signature) { |_sig| } },
  'import' => -> { GPGME::Key.import(exported) },
  'Key.find' => -> { GPGME::Key.find(:public, key) },
}

puts "Ruby #{RUBY_VERSION}, gpgme #{GPGME::gpgme_check_version(nil)}, extension in #{ext_dir}"
puts
puts format('%-18s %11s %16s', 'operation', 'per call', 'longest stall')
ops.each do |name, op|
  op.call
  per_call, gap = with_ticker(ITERATIONS) { op.call }
  puts format('%-18s %s %s', name, ms(per_call), ms(gap))
end

# GPGME.thread_safe, on by default, runs one operation at a time.
%w[verify decrypt\ +\ verify].each do |name|
  op = ops[name]
  puts
  puts "#{name}, #{THREADS * ITERATIONS} calls:"
  start = now
  (THREADS * ITERATIONS).times { op.call }
  serial = now - start
  puts format('  1 thread                    %6.2f s', serial)
  [true, false].each do |thread_safe|
    GPGME.thread_safe = thread_safe
    start = now
    THREADS.times.map { Thread.new { ITERATIONS.times { op.call } } }.each(&:join)
    parallel = now - start
    puts format('  %d threads, thread_safe=%-5s %6.2f s (%.1fx)', THREADS,
                thread_safe, parallel, serial / parallel)
  end
  GPGME.thread_safe = true
end
op = ops['encrypt + sign']

begin
  require 'async'
rescue LoadError
  puts "\nInstall the async gem to measure fiber reactor stalls."
  exit
end

puts
puts 'Async reactor, encrypt + sign in Thread.new { }.join:'
gaps = []
Sync do |task|
  done = false
  heartbeat = task.async do
    last = now
    until done
      sleep TICK
      t = now
      gaps << t - last
      last = t
    end
  end
  ITERATIONS.times { Thread.new { op.call }.join }
  done = true
  heartbeat.wait
end
puts format('  longest stall %s', ms(gaps.max))
