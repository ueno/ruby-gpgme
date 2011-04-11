# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::SubKey do

  # We trust Key for common methods that come from KeyCommon

  it "has certain attributes" do
    subkey = GPGME::Key.find(:secret).first.subkeys.first
    [:pubkey_algo, :length, :keyid, :fpr, :fingerprint].each do |attrib|
      assert subkey.respond_to?(attrib), "Key doesn't respond to #{attrib}"
    end
  end

  it "won't allow the creation of GPGME::SubKey's without the C API" do
    assert_raises NoMethodError do
      GPGME::SubKey.new
    end
  end

end
