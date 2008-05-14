module UMNAuthFilter
  require 'net/https' 
  require 'socket'
  require 'cgi'
  
  mattr_accessor :name
  mattr_accessor :X500_server
  mattr_accessor :X500_https_port
  mattr_accessor :cookiename
  mattr_accessor :logging_enabled
  mattr_accessor :debug_enabled
  mattr_accessor :authorization_redirect
  mattr_accessor :development_mode
  mattr_accessor :development_mode_internet_id

  def self.included(controller)
    controller.extend ClassMethods
    
    @@name ||= "UMN Auth"
    @@x500_server ||= "x500.umn.edu"
    @@x500_https_port ||= 87
    @@cookiename ||= "umnAuthV2"
    @@logging_enabled ||= true
    @@debug_enabled ||= true
    @@authentication_redirect ||= "https://www.umn.edu/login?desturl="
    @@hours_until_cookie_expires ||= 3
    @@validation_module = 'WEBCOOKIE' # Can get switched to WEBCOOKIEG by allow_guest_logins!
    @@validation_level = 30 # Can get changed via allow_guest_logins! to 20, the x500 server must return a number greater than or equal this to be authenticated
    
    @@development_mode = false
    @@development_mode_internet_id = 'development'
  end
  
  module ClassMethods
    
    def umn_auth_filter
      return true if UMNAuthFilter.development_mode
      
      unless request.ssl?
        redirect_to_ssl
        return false
      end
      
      if cookie_expired?
        destroy_umnauth_session
        redirect_to login_and_redirect_url]
        return false
      else
        return true if build_umnauth_session_from_cookie
        destroy_umnauth_session
        
      end
    end
    
  private
  
    def redirect_to_ssl
      redirect_to "https://" + request.host + request.uri
    end
    
    def build_umnauth_session_from_cookie
      x500_response = perform_https_request_to_x500_validation_server
      if x500_response_to_hash(x500_response)
        # TODO: set session[:umnauth]
        return true
      else
        return false
      end
    end
    
    def perform_https_request_to_x500_validation_server(debug_encrypted_cookie_value_string=nil)
      str = debug_encrypted_cookie_value_string ? debug_encrypted_cookie_value_string : cookies[UmnAuthFilter.cookiename]
      retval = ''
      http = Net::HTTP.new(UMNAuthFilter.x500_server, UMNAuthFilter.x500_https_port)
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.use_ssl = true
      the_validation_url = "/#{UMNAuthFilter.validation_module}?x&#{CGI.escape(str)}"
      http.start { |http| retval = http.request( Net::HTTP::Get.new( the_validation_url ) ).body.strip }
      umnauthlog "Response from server: #{retval}" if UMNAuthFilter.logging_enabled
      retval
    end
    
    def x500_response_to_hash(x500_response)
      if is_x500_response_okay?(x500_response)
        fields = x500_response[3..-1].split('|')
        {
         :validation_level => fields[0].to_i,
         :timestamp => fields[1].to_i,
         :ip_address => fields[2],
         :internet_id => fields[3]
        }
      else
        false
      end
    end
    
    def is_x500_response_okay?(x500_response)
      x500_response[0..2] == 'OK:'
      # TODO check against validation level
    end
    
    # sets session[:umnauth] = nil
    def destroy_umnauth_session(controller)
      
    end
    
    def cookie_expired?
      #timestamp = cookies[UmnAuthFilter.cookiename]
      #((Time.now.to_i - previous_timestamp.to_i) / 3600.0) > UmnAuth.hours_until_cookie_expires.to_i
    end
    
    def umnauth_log(str, level=:info)
      # TODO
    end
  end
end