# -*- encoding: utf-8 -*-
require 'test_helper'

##
# I rely on decrypting working. We can test decrypting by generating encrypted
# data that we know is properly encrypted, but not the other way round.
describe GPGME do
  describe :encrypt do
    it "should raise an error if the recipients aren't trusted" do
      assert_raises GPGME::Error::General do
        GPGME.encrypt TEXT[:plain]
      end
    end

    # it "can specify which key(s) to use for encrypting with a string"
    # it "can specify which key to use for encrypting with a Key object"
    # it "can also sign at the same time"
    # it "can be signed by more than one person"
    # it "outputs to a file if specified"
    # it "outputs to something else that responds to write"
  end
end
