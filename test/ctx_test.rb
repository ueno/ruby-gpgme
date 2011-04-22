# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::Ctx do
  it "can instantiate" do
    assert_instance_of GPGME::Ctx, GPGME::Ctx.new
  end

  it "doesn't close itself" do
    GPGME.expects(:gpgme_release).never
    GPGME::Ctx.new
  end

  it "closes itself if called with a block" do
    GPGME.expects(:gpgme_release).with(anything)
    GPGME::Ctx.new { |ctx| }
  end

  it "can be closed with the release method" do
    GPGME.expects(:gpgme_release).with(anything)
    ctx = GPGME::Ctx.new
    ctx.release
  end

  describe :armor do
    it "sets false by default" do
      ctx = GPGME::Ctx.new
      refute ctx.armor
    end

    it "can set" do
      ctx = GPGME::Ctx.new
      ctx.armor = true
      assert ctx.armor
    end

    it "can set and get armor" do
      ctx = GPGME::Ctx.new(:armor => false)
      refute ctx.armor
      ctx = GPGME::Ctx.new(:armor => true)
      assert ctx.armor
    end
  end

  describe :protocol do
    it "sets 0 by default" do
      ctx = GPGME::Ctx.new
      assert_equal 0, ctx.protocol
    end

    it "can set" do
      ctx = GPGME::Ctx.new
      ctx.protocol = 1
      assert_equal 1, ctx.protocol
    end

    it "can set and get protocol" do
      ctx = GPGME::Ctx.new(:protocol => GPGME::PROTOCOL_OpenPGP)
      assert_equal GPGME::PROTOCOL_OpenPGP, ctx.protocol
    end

    it "doesn't allow just any value" do
      assert_raises GPGME::Error::InvalidValue do
        ctx = GPGME::Ctx.new(:protocol => -200)
      end
    end
  end

  describe :textmode do
    it "sets false by default" do
      ctx = GPGME::Ctx.new
      refute ctx.textmode
    end

    it "can set" do
      ctx = GPGME::Ctx.new
      ctx.textmode = true
      assert ctx.textmode
    end

    it "can set and get textmode" do
      ctx = GPGME::Ctx.new(:textmode => false)
      refute ctx.textmode
      ctx = GPGME::Ctx.new(:textmode => true)
      assert ctx.textmode
    end
  end

  describe :keylist_mode do
    it "sets local by default" do
      ctx = GPGME::Ctx.new
      assert_equal GPGME::KEYLIST_MODE_LOCAL, ctx.keylist_mode
    end

    it "can set and get" do
      ctx = GPGME::Ctx.new(:keylist_mode => GPGME::KEYLIST_MODE_SIGS)
      assert_equal GPGME::KEYLIST_MODE_SIGS, ctx.keylist_mode
    end

    it "can set" do
      ctx = GPGME::Ctx.new
      ctx.keylist_mode = GPGME::KEYLIST_MODE_SIGS
      assert_equal GPGME::KEYLIST_MODE_SIGS, ctx.keylist_mode
    end

    it "allows the four possible values" do
      [GPGME::KEYLIST_MODE_LOCAL, GPGME::KEYLIST_MODE_EXTERN,
      GPGME::KEYLIST_MODE_SIGS, GPGME::KEYLIST_MODE_VALIDATE].each do |mode|
        GPGME::Ctx.new(:keylist_mode => mode)
      end
    end

    # It's not crashing?
    # it "crashes with other values" do
    #   GPGME::Ctx.new(:keylist_mode => -200)
    # end
  end

  describe "keylist operations" do
    it "can return all of the keys" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys
      ctx.release

      assert keys.size >= 4
      assert_equal KEYS.map{|k| k[:sha]}, keys.map{|key| key.uids.first.email}
    end

    it "can return keys filtering by a pattern" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys(KEYS.first[:sha])
      ctx.release

      assert_equal 1, keys.size
      assert_equal KEYS.first[:sha], keys.first.email
    end

    it "can return only secret keys" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys(KEYS.first[:sha], true)
      ctx.release

      assert keys.all?(&:secret?)
    end

    it "can return only public keys" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys(KEYS.first[:sha], false)
      ctx.release

      refute keys.any?(&:secret?)
    end

    it "returns only public keys by default" do
      ctx = GPGME::Ctx.new
      keys = ctx.keys(KEYS.first[:sha])
      ctx.release

      refute keys.any?(&:secret?)
    end

    it "can iterate through them returning only public keys" do
      GPGME::Ctx.new do |ctx|
        ctx.each_key do |key|
          assert_instance_of GPGME::Key, key
          refute key.secret?
        end
      end
    end

    it "can iterate through them getting only private ones" do
      GPGME::Ctx.new do |ctx|
        ctx.each_key("", true) do |key|
          assert_instance_of GPGME::Key, key
          assert key.secret?
        end
      end
    end

    it "can iterate through them filtering by pattern" do
      num = 0
      GPGME::Ctx.new do |ctx|
        ctx.each_key(KEYS.first[:sha]) do |key|
          assert_instance_of GPGME::Key, key
          assert_equal KEYS.first[:sha], key.email
          num += 1
        end
      end
      assert_equal 1, num
    end

    it "can get only a specific key" do
      GPGME::Ctx.new do |ctx|
        key = ctx.get_key(KEYS.first[:sha])
        assert_instance_of GPGME::Key, key
        assert_equal KEYS.first[:sha], key.email
      end
    end
  end



end
