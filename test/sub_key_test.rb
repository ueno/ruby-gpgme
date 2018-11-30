# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::SubKey do
  before do
    skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
  end

  # We trust Key for common methods that come from KeyCommon

  it "has certain attributes" do
    subkey = GPGME::Key.find(:secret).first.primary_subkey
    [:pubkey_algo, :length, :keyid, :fpr, :fingerprint].each do |attrib|
      assert subkey.respond_to?(attrib), "Key doesn't respond to #{attrib}"
    end
  end

  it "won't allow the creation of GPGME::SubKey's without the C API" do
    assert_raises NoMethodError do
      GPGME::SubKey.new
    end
  end

  it "knows if the key is expired" do
    subkey = GPGME::Key.find(:secret).first.primary_subkey
    refute subkey.expired

    with_key EXPIRED_KEY do
      key = GPGME::Key.find(:secret, EXPIRED_KEY[:sha]).first
      if key
        subkey = key.primary_subkey
        assert subkey.expired
      end
    end
  end

  describe :inspect do
    it "can be inspected" do
      subkey = GPGME::Key.find(:secret).first.primary_subkey
      subkey.inspect
    end
  end

  describe :to_s do
    it "can be coerced into a String" do
      subkey = GPGME::Key.find(:secret).first.primary_subkey
      subkey.to_s
    end
  end

end
