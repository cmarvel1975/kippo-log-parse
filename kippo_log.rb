require 'ap'
require 'colored'
require_relative 'lib/kippo_log_parse'

LOGFILE = File.open("/home/kippo/kippo/log/kippo.log")

LOGFILE.each do |line|
  Kippo_log_parse.new.parse(line)
end
