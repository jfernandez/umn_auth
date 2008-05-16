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
    @@name ||= "UMN Auth"
    @@x500_server ||= "x500.umn.edu"
    @@x500_https_port ||= 87
    @@cookiename ||= "umnAuthV2"
    @@logging_enabled ||= true
    @@debug_enabled ||= true
    @@authentication_login_redirect ||= "https://www.umn.edu/login?desturl="
    @@authentication_logut_redirect ||= "https://www.umn.edu/logout?desturl="
    @@hours_until_cookie_expires ||= 3
    @@validation_module = 'WEBCOOKIE' # Can get switched to WEBCOOKIEG by allow_guest_logins!
    @@validation_level = 30 # Can get changed via allow_guest_logins! to 20, the x500 server must return a number greater than or equal this to be authenticated
    @@development_mode = false
    @@development_mode_internet_id = 'development'
    
    controller.helper_method(:login_and_redirect_url, :logout_and_redirect_url)
  end
  
  def login_and_redirect_url(redirect_url=nil)
    redirect_url ||= request.url
    @@authentication_login_redirect + ERB::Util.url_encode(redirect_url)
  end
  
  def logout_and_redirect_url(redirect_url=nil)
    redirect_url ||= request.url
    @@authentication_logout_redirect + ERB::Util.url_encode(redirect_url)
  end
    
protected
    
  def umn_auth_required
    return true if @@development_mode
    
    unless request.ssl?
      redirect_to_ssl
      return false
    end
    
    if session_expired?
      destroy_umnauth_session
      redirect_to login_and_redirect_url
      return false
    end
    
    return true if build_umnauth_session_from_cookie
    
    destroy_umnauth_session
    redirect_to login_an_redirect_url
    return false
  end
  
private

  def redirect_to_ssl
    redirect_to "https://" + request.host_with_port + request.uri
  end
  
  def build_umnauth_session_from_cookie
    x500_response = perform_https_request_to_x500_validation_server
    return false unless is_x500_response_okay?(x500_response)
    session[:umnauth] = UMNAuthCookie.new(x500_response)
  end
  
  def perform_https_request_to_x500_validation_server(debug_encrypted_cookie_value_string=nil)
    str = debug_encrypted_cookie_value_string ? debug_encrypted_cookie_value_string : cookies[UmnAuthFilter.cookiename]
    retval = ''
    http = Net::HTTP.new(@@x500_server, @@x500_https_port)
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.use_ssl = true
    validation_uri = "/#{@@validation_module}?x&#{CGI.escape(str)}"
    http.start { |http| retval = http.request( Net::HTTP::Get.new( validation_uri ) ).body.strip }
    umnauthlog "Response from server: #{retval}" if @@logging_enabled
    retval
  end
  
  # [DEPRECATED] The UmnAuthCookie class should perform the validation
  def x500_response_to_hash(x500_response)
    return false unless is_x500_response_okay?(x500_response)
    fields = x500_response[3..-1].split('|')
    {
      :validation_level => fields[0].to_i,
      :timestamp => fields[1].to_i,
      :ip_address => fields[2],
      :internet_id => fields[3]
    }
  end
  
  def is_x500_response_okay?(x500_response)
    str = x500_response.split('|').first.split(':')
    str.first == 'OK' && str.last >= @@validation_level
  end
  
  def destroy_umnauth_session(controller)
    session[:umnauth] = nil
  end
  
  def session_expired?
    timestamp = session[:umnauth].timestamp.to_i
    ((Time.now.to_i - time.to_i) / 3600.0) > @@hours_until_cookie_expires.to_i
  end
  
  def umnauth_log(str, level=:info)
    # TODO
  end
end