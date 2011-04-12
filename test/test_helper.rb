# -*- encoding: utf-8 -*-
require 'bundler/setup'
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/pride'
require 'mocha'
require 'ruby-debug'
require 'gpgme'

require File.dirname(__FILE__) + "/support/resources"

def import_keys
  GPGME.import KEY[:public]
  GPGME.import KEY[:private]
end

def remove_keys
  GPGME::Ctx.new do |ctx|
    GPGME.list_keys(KEY[:sha]).each do |key|
      ctx.delete_key key, true
    end
  end
end

# Import a key pair at the beginning to be used throughout the tests
puts "Importing keys..."
import_keys

# Remove the tests key at the end of test execution
MiniTest::Unit.after_tests do
  remove_keys
end
