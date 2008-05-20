require 'umn_auth'
ActiveResource::Base.send(:include, UmnAuth::Authenticated)