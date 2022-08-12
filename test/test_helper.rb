# -*- encoding: utf-8 -*-

require 'coveralls'
Coveralls.wear!

# include compiled gpgme_n.bundle
tmp_dir = File.join(File.dirname(__FILE__), '..', 'tmp')
$:.unshift(tmp_dir) if File.directory?(tmp_dir)

# this interfers otherwise with our tests
ENV.delete('GPG_AGENT_INFO')

require 'rubygems'
require 'bundler/setup'
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/pride'
require 'mocha'
require 'gpgme'

if RUBY_VERSION.split('.').first.to_i > 1
  require 'byebug'
else
  require 'ruby-debug'
end

require File.dirname(__FILE__) + "/support/resources"


def import_keys
  KEYS.each do |key|
    import_key(key)
  end
end

def import_key(key, only = :all)
  GPGME::Key.import(key[:public]) unless only == :secret
  GPGME::Key.import(key[:secret]) unless only == :public
end

def remove_keys
  KEYS.each do |key|
    remove_key(key)
  end
end

def remove_all_keys
  GPGME::Key.find(:public).each do |k|
    k.delete!(true)
  end
  GPGME::Key.find(:secret).each do |k|
    k.delete!(true)
  end
end

def remove_key(key)
  GPGME::Key.find(:public, key[:sha]).each do |k|
    k.delete!(true)
  end
  GPGME::Key.find(:secret, key[:sha]).each do |k|
    k.delete!(true)
  end
end

def with_key(key, only = :all, &block)
  import_key key, only

  begin
    yield
  ensure
    remove_key key
  end
end

def without_key(key, &block)
  remove_key key

  begin
    yield
  ensure
    import_key key
  end
end

DIRS = []

at_exit do
  DIRS.each do |dir|
    FileUtils.remove_entry dir
  end
  DIRS.clear
end

def ensure_keys(proto)
  return false unless GPGME::Engine.check_version proto

  case proto
  when GPGME::PROTOCOL_OpenPGP
    # We use a different home directory for the keys to not disturb current
    # installation
    require 'tmpdir'
    require 'pathname'

    if DIRS.empty?
      dir = Dir.mktmpdir
      GPGME::Engine.home_dir = dir
      DIRS.push(dir)
      pinentry = Pathname.new(__FILE__).dirname + 'pinentry'
      gpg_agent_conf = Pathname.new(dir) + 'gpg-agent.conf'
      gpg_agent_conf.open('w+') {|io|
        io.write("pinentry-program #{pinentry}\n")
      }
      remove_all_keys
      import_keys
    end
    true
  else
    return false
  end
end
