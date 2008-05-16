module UmnAuth
  class Session
    attr_reader :validation_level, :timestamp, :ip_address, :internet_id, :authentication_token

    def initialize(str, token)
      return unless str[0..2] == "OK:"
      fields = str[3..-1].split('|')
      @validation_level = fields[0].to_i
      @timestamp = fields[1].to_i
      @ip_address = fields[2]
      @internet_id = fields[3]
      @authentication_token = token
    end
    
    def valid_token?(token)
      @authentication_token == token         
    end
    
    def valid_ip?(ip)
      @ip_address == ip
    end
    
    def expired?
      ((Time.now.to_i - @timestamp) / 3600.0) > UmnAuth.hours_until_cookie_expires
    end
    
    def valid?(token, ip)
      valid_token?(token) && valid_ip?(ip) && !expired?
    end

    def authentication_method
      case @validation_level.to_i
      when 5
        "Forced password change - protected web servers must NOT allow access at this level"
      when 10
        "Guest account"
      when 20
        "User initiated their account for the first time"
      when 30
        "Internet password"
      when 40
        "Enterprise password"
      when 50
        "Two-factor"
      else
        "Unknown"
      end
    end
  end
end
