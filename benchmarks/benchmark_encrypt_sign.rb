# -*- encoding: utf-8 -*-
# Benchmark to investigate encryption vs encryption+signing performance
require_relative '../test/test_helper'

# Simple timing helper since benchmark is no longer in stdlib
def measure(label, n = 5)
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  n.times { yield }
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  puts "#{label.ljust(30)} #{elapsed.round(4)}s total, #{(elapsed / n).round(4)}s per iteration"
  elapsed
end

# Profiling helper to trace where time is spent
def profile_encrypt_sign
  plain_text = "Hello, World! " * 100
  crypto = GPGME::Crypto.new(always_trust: true)
  key = KEYS.first[:sha]

  puts "\n=== Profiling encrypt only ==="
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  keys = GPGME::Key.find(:public, key)
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  puts "Key.find for recipients: #{((t1 - t0) * 1000).round(2)}ms"

  GPGME::Ctx.new(always_trust: true) do |ctx|
    t2 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "Ctx.new: #{((t2 - t1) * 1000).round(2)}ms"

    plain_data = GPGME::Data.new(plain_text)
    cipher_data = GPGME::Data.new
    ctx.encrypt(keys, plain_data, cipher_data, GPGME::ENCRYPT_ALWAYS_TRUST)
    t3 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "encrypt: #{((t3 - t2) * 1000).round(2)}ms"
  end

  puts "\n=== Profiling encrypt + sign (no explicit signer) ==="
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  keys = GPGME::Key.find(:public, key)
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  puts "Key.find for recipients: #{((t1 - t0) * 1000).round(2)}ms"

  GPGME::Ctx.new(always_trust: true) do |ctx|
    t2 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "Ctx.new: #{((t2 - t1) * 1000).round(2)}ms"

    plain_data = GPGME::Data.new(plain_text)
    cipher_data = GPGME::Data.new
    ctx.encrypt_sign(keys, plain_data, cipher_data, GPGME::ENCRYPT_ALWAYS_TRUST)
    t3 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "encrypt_sign: #{((t3 - t2) * 1000).round(2)}ms"
  end

  puts "\n=== Profiling encrypt + sign (with explicit signer - current code) ==="
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  keys = GPGME::Key.find(:public, key)
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  puts "Key.find for recipients: #{((t1 - t0) * 1000).round(2)}ms"

  signers = GPGME::Key.find(:public, key, :sign)
  t2 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  puts "Key.find for signers: #{((t2 - t1) * 1000).round(2)}ms"

  GPGME::Ctx.new(always_trust: true) do |ctx|
    t3 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "Ctx.new: #{((t3 - t2) * 1000).round(2)}ms"

    ctx.add_signer(*signers)
    t4 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "add_signer: #{((t4 - t3) * 1000).round(2)}ms"

    plain_data = GPGME::Data.new(plain_text)
    cipher_data = GPGME::Data.new
    ctx.encrypt_sign(keys, plain_data, cipher_data, GPGME::ENCRYPT_ALWAYS_TRUST)
    t5 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "encrypt_sign: #{((t5 - t4) * 1000).round(2)}ms"
  end

  puts "\n=== Key.find cost breakdown ==="
  10.times do |i|
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    GPGME::Key.find(:public, key)
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "Key.find iteration #{i + 1}: #{((t1 - t0) * 1000).round(2)}ms"
  end
end

# Ensure keys are imported
import_keys

plain_text = "Hello, World! " * 1000  # ~14KB of data

crypto = GPGME::Crypto.new(always_trust: true)
key = KEYS.first[:sha]

puts "Data size: #{plain_text.bytesize} bytes"
puts

n = 50

measure("encrypt only:", n) do
  crypto.encrypt(plain_text, recipients: key)
end

measure("encrypt + sign:", n) do
  crypto.encrypt(plain_text, recipients: key, sign: true)
end

measure("sign only:", n) do
  crypto.sign(plain_text)
end

puts
puts "Running with explicit signer..."
puts

measure("encrypt + sign (explicit):", n) do
  crypto.encrypt(plain_text, recipients: key, sign: true, signers: key)
end

# Run detailed profiling
profile_encrypt_sign
