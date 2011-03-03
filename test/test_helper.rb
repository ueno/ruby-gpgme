# -*- encoding: utf-8 -*-
require 'bundler/setup'
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/pride'
require 'mocha'
require 'ruby-debug'
require 'gpgme'

require File.dirname(__FILE__) + "/support/resources"

# Import a key pair at the beginning to be used throughout the tests
puts "Importing keys..."
GPGME.import KEY[:public]
GPGME.import KEY[:private]

# Remove the tests key at the end of test execution
MiniTest::Unit.after_tests do
  GPGME::Ctx.new do |ctx|
    key = GPGME.list_keys(KEY[:sha]).first
    ctx.delete_key key, true
  end
end
