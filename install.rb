require 'fileutils'

umn_auth_users = File.dirname(__FILE__) + '/../../../config/umn_auth_users.yml'
FileUtils.cp File.dirname(__FILE__) + '/umn_auth_users.yml.tpl', umn_auth_users unless File.exist?(umn_auth_users)
puts IO.read(File.join(File.dirname(__FILE__), 'README'))