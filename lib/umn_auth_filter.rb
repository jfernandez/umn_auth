class UMNAuthFilter
  cattr_accessor :name
  cattr_accessor :X500_server
  cattr_accessor :X500_https_port
  cattr_accessor :cookiename
  cattr_accessor :logging_enabled
  cattr_accessor :debug_enabled
  cattr_accessor :authorization_redirect
  
  require 'net/https'

  def self.filter(controller)
    @@name ||= "UMN Auth"
    @@x500_server ||= "x500.umn.edu"
    @@x500_https_port ||= 87
    @@cookiename ||= "umnAuthV2"
    @@logging_enabled ||= true
    @@debug_enabled ||= true
    @@authentication_redirect ||= "https://www.umn.edu/login?desturl="
    @@hours_until_cookie_expires ||= 3
    
    umnauth_cookie = controller.send(:cookies)[@@cookiename]
    umnauth_session = controller.send(:session)[:umnauth]
    request = controller.send :request
    authorized = false
    
    umnauth_session = nil

    if umnauth_session and umnauth_cookie
      # Even if the user has been previously verified they could have logged
      # out, so the existence of the cookie always has to be checked.
      umnauthlog( controller, "User previously verified." )
      if check_time( controller, umnauth_session.timestamp )
        authenticated = true
      end

    elsif umnauth_cookie
      umnauthlog controller, "Checking unverified user from #{request.remote_ip} with cookie #{@@cookiename} present."
      umnauthlog controller, "Cookie contents: #{umnauth_cookie}.", :warn if @@debug_enabled

      x500_response = check_cookie_with_authority( controller, umnauth_cookie )
      
      if x500_response[0..1] == 'OK'
        umnauth_session = UMNAuthCookie.new( x500_response )
        
        # verify address
        if umnauth_session.ip_address == request.remote_ip
          if check_time( controller, umnauth_session.timestamp )
            umnauthlog controller, "Verification success.  Validation level: #{umnauth_session.validation_level}, #{umnauth_session.authentication_method}"
            authenticated = true
          end
        else
          umnauthlog controller, "Verification failure.  IP address mismatch - Cookie: #{umnauth_session.ip_address}, request.remote_ip: #{request.remote_ip}"
        end
 
      else
        umnauthlog controller, "Verification failure.  Rejected by X500 server."  
      end
      
    else
      if request.protocol !~ %r{^https}
        umnauthlog controller, "Cookie #{@@cookiename} not present or can't be read.  Is the cookie marked as secure while being requested from an unsecure port?", :warn
      else
        umnauthlog controller, "Cookie #{@@cookiename} not present."
      end
    end
    
    unless authenticated
      # TODO: Check that a server_port isn't being added when it wasn't specified in the URL.
      intended_destination = if request.server_port
          "#{request.protocol}#{request.server_name}:#{request.server_port}#{request.request_uri}"
        else
          "#{request.protocol}#{request.server_name}#{request.request_uri}"
        end

      controller.send(:session)[:umnauth] = nil
      controller.send :redirect_to, "#{@@authentication_redirect}#{ERB::Util.url_encode(intended_destination)}"
      
      # NOTE: don't return false, filter chains would be displeased
      # http://api.rubyonrails.org/classes/ActionController/Filters/ClassMethods.html
      return
    end
    
    controller.send( "session" )[:umnauth] = umnauth_session
  end
  
  #######
  private
  #######
  
  def self.umnauthlog( controller, str, level=:info )
    controller.send( "logger" ).method(level).call("[#{@@name}] #{str}") if @@logging_enabled
  end

  def self.check_cookie_with_authority( controller, str )
    retval = ''
    http = Net::HTTP.new(@@x500_server, @@x500_https_port)
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.use_ssl = true
    http.start { |http| retval = http.request( Net::HTTP::Get.new( "/WEBCOOKIE?x&#{str}" ) ).body.strip }
    umnauthlog controller, "Response from server: #{retval}"
    retval
  end
  
  def self.check_time( controller, previous_timestamp )
    # 3600 seconds in an hour, .0 to force Float conversion
    if ((Time.now.to_i - previous_timestamp.to_i) / 3600.0) > @@hours_until_cookie_expires.to_i
      umnauthlog controller, "Cookie #{@@cookiename} has expired.  #{previous_timestamp.to_i / 3600.0} hours old"
      umnauthlog controller, "#{@@hours_until_cookie_expires} is the limit.", :warn if @@debug_enabled
      return false
    end
    true
  end
end

