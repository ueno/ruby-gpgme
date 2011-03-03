# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME do
  it "does the roundtrip encrypting" do
    encrypted = GPGME.encrypt [KEY[:sha]], TEXT[:plain], :always_trust => true
    assert_equal TEXT[:plain], GPGME.decrypt(encrypted)
  end

  it "does so even with armored encrypted stuff" do
    encrypted = GPGME.encrypt [KEY[:sha]], TEXT[:plain],
      :always_trust => true, :armor => true
    assert_equal TEXT[:plain], GPGME.decrypt(encrypted)
  end

  describe :encrypt do
    it "should raise an error if the recipients aren't trusted" do
      assert_raises GPGME::Error::General do
        GPGME.encrypt [KEY[:sha]], TEXT[:plain]
      end
    end

    it "can specify which key to use for encrypting with a string"
    it "can specify which key to use for encrypting with a Key object"
    it "can also sign at the same time"
    it "can be signed by more than one person"
    it "outputs to a file if specified"
    it "outputs to something else that responds to write"
  end
end
