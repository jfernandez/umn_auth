require 'spec_helper'

describe UmnAuth::Session do
  let(:str) { "OK:30|1299431105|192.168.1.1|user123|" }
  let(:token) { "tokenABC123" }
  
  before(:each) do
    @session = UmnAuth::Session.new(str, token)
  end
  
  describe "#initialize" do
    it "correctly parses and sets the validation_level attribute from the 'str' parameter" do
      @session.validation_level.should == 30
    end
    
    it "correctly parses and sets the timestamp attribute from the 'str' parameter" do
      @session.timestamp.should == 1299431105
    end
    
    it "correctly parses and sets the ip_address attribute from the 'str' parameter" do
      @session.ip_address.should == "192.168.1.1"
    end
    
    it "correctly parses and sets the internet_id attribute from the 'str' parameter" do
      @session.internet_id.should == "user123"
    end
    
    it "correctly sets the authentication_token attribute from the 'token' parameter" do
      @session.authentication_token.should == token
    end
  end
  
  describe "#valid_token?" do
    it "returns true when the supplied token matches the authentication_token attributes" do
      @session.valid_token?(token).should be_true
    end
    
    it "returns false when the supplied token does not match the authentication_token attribute" do
      @session.valid_token?("badtoken").should be_false
    end
  end
  
  describe "#valid_ip?" do
    it "returns true when the supplied ip_address matches the ip_address attribute" do
      @session.valid_ip?("192.168.1.1").should be_true
    end
    
    it "returns false when the supplied ip_address is different than the ip_address attribute" do
      @session.valid_ip?("123.123.123.123").should be_false
    end
  end
  
  describe "#expired?" do
    it "returns true when the timestamp attribute is older than the 'hours_to_expire' value" do
      seconds = 2 * 60 * 60
      two_hours_ago = (Time.now - seconds).to_i
      @expired_session = UmnAuth::Session.new("OK:30|#{two_hours_ago}|192.168.1.1|user123|", token)
      @expired_session.expired?(1).should be_true
    end
    
    it "returns false when the timestamp attribute is within the 'hours_to_expire' value" do
      seconds = 2 * 60 * 60
      two_hours_ago = (Time.now - seconds).to_i
      @expired_session = UmnAuth::Session.new("OK:30|#{two_hours_ago}|192.168.1.1|user123|", token)
      @expired_session.expired?(3).should be_false
    end
  end
end