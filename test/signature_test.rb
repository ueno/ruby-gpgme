# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::Signature do
  before do
    skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
  end

  it "#valid? is true when the signature is valid" do
    crypto = GPGME::Crypto.new
    signatures = 0
    sign = crypto.sign "Hi there"

    crypto.verify(sign) do |signature|
      assert_instance_of GPGME::Signature, signature
      assert signature.valid?
      refute signature.expired_signature?
      refute signature.expired_key?
      refute signature.revoked_key?
      refute signature.bad?
      refute signature.no_key?
      signatures += 1
    end

    assert_equal 1, signatures
  end

  it "#expired_key? is true when the key has expired" do
    with_key EXPIRED_KEY do
      crypto = GPGME::Crypto.new
      signatures = 0
      crypto.verify(TEXT[:expired_key_sign]) do |signature|
        assert_instance_of GPGME::Signature, signature
        refute signature.valid?
        refute signature.expired_signature?
        assert signature.expired_key?
        refute signature.revoked_key?
        refute signature.bad?
        refute signature.no_key?
        signatures += 1
      end

      assert_equal 1, signatures
    end
  end

  # TODO Find how to test these
  # it "#expired_signature? is true when the signature has expired"
  # it "#revoked_key? is true when the key has been revoked"
  # it "#bad? is true when the signature is bad"
  # it "#no_key? is true when we don't have the key to verify the signature"
end
