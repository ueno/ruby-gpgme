require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake/testtask'
require 'rcov/rcovtask'
require 'yard'


desc "Re-compile the extensions"
task :compile do
  FileUtils.rm_rf('tmp') if File.directory?('tmp')
  mkdir 'tmp'

  Dir.chdir('tmp') do
    system "ruby #{File.dirname(__FILE__)}/ext/gpgme/extconf.rb"
    system "make"
  end
end

task :default => [:test]

Rake::TestTask.new(:test => :compile) do |t|
  t.libs << 'test'
  t.pattern = "test/**/*_test.rb"
  t.verbose = true
end
Rake::Task['test'].comment = "Run all tests"

YARD::Rake::YardocTask.new

Rcov::RcovTask.new do |t|
  t.libs << 'test'
  t.pattern = "test/**/*_test.rb"
  t.verbose = true
  t.rcov_opts = ["-x gems"]
end

