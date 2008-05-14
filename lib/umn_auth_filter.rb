module UMNAuthFilter
  require 'net/https'
  
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
        # TODO
      else
        
      end
      # TODO
    end
    
  private
  
    def redirect_to_ssl
      redirect_to "https://" + request.host + request.uri
    end
    
    def cookie_expired?
      timestamp = cookies[UmnAuthFilter.cookiename]
      ((Time.now.to_i - previous_timestamp.to_i) / 3600.0) > UmnAuth.hours_until_cookie_expires.to_i
    end
    
  end
end