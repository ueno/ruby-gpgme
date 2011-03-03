require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake/testtask'
require 'yard'

task :default => [:test]

Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.pattern = "test/**/*_test.rb"
  t.verbose = true
end
Rake::Task['test'].comment = "Run all tests"

YARD::Rake::YardocTask.new do |t|
  # t.files   = ['lib/*.rb']
end
