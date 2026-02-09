# -*- encoding: utf-8 -*-
require 'test_helper'

describe 'GPGME Encryption Flags' do
  it 'should expose ENCRYPT_ALWAYS_TRUST' do
    assert_equal 1, GPGME::ENCRYPT_ALWAYS_TRUST
  end

  it 'should expose ENCRYPT_NO_ENCRYPT_TO if available' do
    if defined?(GPGME::ENCRYPT_NO_ENCRYPT_TO)
      assert GPGME::ENCRYPT_NO_ENCRYPT_TO.is_a?(Integer)
    end
  end

  it 'should expose ENCRYPT_PREPARE if available' do
    if defined?(GPGME::ENCRYPT_PREPARE)
      assert GPGME::ENCRYPT_PREPARE.is_a?(Integer)
    end
  end

  it 'should expose ENCRYPT_EXPECT_SIGN if available' do
    if defined?(GPGME::ENCRYPT_EXPECT_SIGN)
      assert GPGME::ENCRYPT_EXPECT_SIGN.is_a?(Integer)
    end
  end

  it 'should expose ENCRYPT_NO_COMPRESS if available' do
    if defined?(GPGME::ENCRYPT_NO_COMPRESS)
      assert GPGME::ENCRYPT_NO_COMPRESS.is_a?(Integer)
    end
  end

  it 'should expose ENCRYPT_UNSIGNED_INTEGRITY_CHECK if available' do
    if defined?(GPGME::ENCRYPT_UNSIGNED_INTEGRITY_CHECK)
      assert GPGME::ENCRYPT_UNSIGNED_INTEGRITY_CHECK.is_a?(Integer)
    end
  end

  it 'should expose ENCRYPT_SYMMETRIC if available' do
    if defined?(GPGME::ENCRYPT_SYMMETRIC)
      assert GPGME::ENCRYPT_SYMMETRIC.is_a?(Integer)
    end
  end

  it 'should expose ENCRYPT_THROW_KEYIDS if available' do
    if defined?(GPGME::ENCRYPT_THROW_KEYIDS)
      assert GPGME::ENCRYPT_THROW_KEYIDS.is_a?(Integer)
    end
  end

  it 'should use different flag values for different flags' do
    flags = []
    flags << GPGME::ENCRYPT_ALWAYS_TRUST
    flags << GPGME::ENCRYPT_NO_ENCRYPT_TO if defined?(GPGME::ENCRYPT_NO_ENCRYPT_TO)
    flags << GPGME::ENCRYPT_PREPARE if defined?(GPGME::ENCRYPT_PREPARE)
    flags << GPGME::ENCRYPT_EXPECT_SIGN if defined?(GPGME::ENCRYPT_EXPECT_SIGN)
    flags << GPGME::ENCRYPT_NO_COMPRESS if defined?(GPGME::ENCRYPT_NO_COMPRESS)
    flags << GPGME::ENCRYPT_UNSIGNED_INTEGRITY_CHECK if defined?(GPGME::ENCRYPT_UNSIGNED_INTEGRITY_CHECK)
    flags << GPGME::ENCRYPT_SYMMETRIC if defined?(GPGME::ENCRYPT_SYMMETRIC)
    flags << GPGME::ENCRYPT_THROW_KEYIDS if defined?(GPGME::ENCRYPT_THROW_KEYIDS)

    # All flags should be unique
    assert_equal flags.length, flags.uniq.length
  end
end
