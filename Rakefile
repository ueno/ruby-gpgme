require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake/testtask'
require 'rcov/rcovtask'
require 'yard'


desc "Re-compile the extensions"
task :compile do
  FileUtils.rm_f('gpgme_n.bundle')
  FileUtils.rm_f('gpgme_n.o')
  FileUtils.rm_f('Makefile')

  system "ruby extconf.rb"
  system "make"
end

task :default => [:test]

Rake::TestTask.new(:test) do |t|
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

