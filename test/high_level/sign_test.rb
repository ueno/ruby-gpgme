# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME do
  describe :sign do
    it "signs normal strings" do
      signatures = 0
      sign = GPGME.sign "Hi there"

      GPGME.verify(sign) do |signature|
        assert_instance_of GPGME::Signature, signature
        signatures += 1
      end

      assert_equal 1, signatures
    end
  end
end

