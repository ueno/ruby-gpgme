# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::Key do

  it "has certain attributes" do
    key = GPGME::Key.find(:secret).first
    [:keylist_mode, :protocol, :owner_trust, :issuer_serial,
      :issuer_name, :chain_id, :subkeys, :uids].each do |attrib|
      assert key.respond_to?(attrib), "Key doesn't respond to #{attrib}"
    end
  end

  it "won't allow the creation of GPGME::Key's without the C API" do
    assert_raises NoMethodError do
      GPGME::Key.new
    end
  end

  describe :find do
    it "should return all by default" do
      keys = GPGME::Key.find :secret
      assert_instance_of GPGME::Key, keys.first
      assert 0 < keys.size
    end

    it "returns an array even if you pass only one descriptor" do
      keys_one   = GPGME::Key.find(:secret, KEY[:sha]).map{|key| key.subkeys.map(&:keyid)}
      keys_array = GPGME::Key.find(:secret, [KEY[:sha]]).map{|key| key.subkeys.map(&:keyid)}
      assert_equal keys_one, keys_array
    end

    it "returns only secret keys if told to do so" do
      keys = GPGME::Key.find :secret
      assert keys.all?(&:secret?)
    end

    it "returns only public keys if told to do so" do
      keys = GPGME::Key.find :public
      assert keys.none?(&:secret?)
    end

    it "filters by capabilities" do
      GPGME::Key.any_instance.stubs(:usable_for?).returns(false)
      keys = GPGME::Key.find :public, "", :wadusing
      assert keys.empty?
    end
  end

  # describe :trust do
  #   it "returns :revoked if it is so"
  #   it "returns :expired if it is expired"
  #   it "returns :disabled if it is so"
  #   it "returns :invalid if it is so"
  #   it "returns nil otherwise"
  # end

  # describe :capability do
  #   it "returns an array of possible capabilities"
  # end

  # describe :secret? do
  #   "returns true/false depending on the instance variable"
  # end

  describe :usable_for? do
    it "checks for the capabilities of the key and returns true if it matches all" do
      key = GPGME::Key.find(:secret).first

      key.stubs(:capability).returns([:encrypt, :sign])
      assert key.usable_for?([])

      key.stubs(:capability).returns([:encrypt, :sign])
      assert key.usable_for?([:encrypt])

      key.stubs(:capability).returns([:encrypt, :sign])
      refute key.usable_for?([:certify])
    end

    it "returns false if the key is expired or revoked or disabled or disabled" do
      key = GPGME::Key.find(:secret).first
      key.stubs(:trust).returns(:revoked)
      key.stubs(:capability).returns([:encrypt, :sign])
      refute key.usable_for?([:encrypt])
    end
  end

end

