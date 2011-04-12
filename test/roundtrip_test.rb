# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME do
  it "does the roundtrip encrypting" do
    encrypted = GPGME.encrypt TEXT[:plain], :always_trust => true
    assert_equal TEXT[:plain], GPGME.decrypt(encrypted).read
  end

  it "does so even with armored encrypted stuff" do
    encrypted = GPGME.encrypt TEXT[:plain], :always_trust => true, :armor => true
    assert_equal TEXT[:plain], GPGME.decrypt(encrypted).read
  end
end
