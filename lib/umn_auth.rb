module UmnAuth
  require 'umn_auth/session'
  require 'net/https' 
  require 'socket'
  require 'cgi'
  
  mattr_reader :development_mode
  mattr_reader :development_mode_internet_id
  
  def self.included(controller)
    options = {
      :name => "UMN Auth",
      :token_name => "umnAuthV2",
      :x500_server => "x500.umn.edu",
      :x500_https_port => 87,
      :logging_enabled => true,
      :debug_enabled => true,
      :authentication_login_redirect => "https://www.umn.edu/login?desturl=",
      :authentication_logut_redirect => "https://www.umn.edu/logout?desturl=",
      :hours_until_cookie_expires => 3,
      :validation_module => "WEBCOOKIE",
      :validation_level => 30
    }
    UmnAuth.development_mode ||= false
    UmnAuth.development_mode_internet_id ||= 'development'
    controller.write_inheritable_hash(:umn_auth_options, options)
    controller.class_inheritable_accessor(:umn_auth_options)
    controller.helper_method(:login_and_redirect_url, :logout_and_redirect_url, :current_umn_session)
  end
  
  def login_and_redirect_url(redirect_url=nil)
    redirect_url ||= request.url
    self.umn_auth_options[:authentication_login_redirect] + ERB::Util.url_encode(redirect_url)
  end
  
  def logout_and_redirect_url(redirect_url=nil)
    redirect_url ||= request.url
    self.umn_auth_options[:authentication_login_redirect] + ERB::Util.url_encode(redirect_url)
  end
  
  def current_umn_session
    session[:umn_auth].nil? ? false : session[:umn_auth]
  end

  def umn_auth_required(*args)
    self.umn_auth_options.merge!(args.extract_options!)
    
    unless UmnAuth.development_mode && cookies[self.umn_auth_options[:token_name]].nil?
      redirect_to(login_and_redirect_url)
      return false
    end
    
    build_umn_session_from_cookie unless current_umn_session
    
    if current_umn_session_x500_valid?
      return true if authorized_by_validation_level?
      access_denied
      return false
    else
      destroy_umn_session  
      redirect_to(login_and_redirect_url)
      return false
    end
  end

protected
  
  # Redirect as appropriate when the authorized_by_validation_level? check fails
  #
  # The default action is to redirect to x500 login screen
  #
  # Override this method in your controllers if you want to have special
  # behavior in case the user doesn't have the required validation level
  # to access the requested action.
  def access_denied
    redirect_to(logout_and_redirect_url)
  end
  
private
  
  def development_mode_x500_response
    "OK:30|#{Time.now.to_i}|127.0.0.1|#{UmnAuth.development_mode_internet_id}|"
  end
  
  def current_umn_session_x500_valid?
    (
      current_umn_session &&  
      current_umn_session.valid_ip?(request.remote_ip) &&
      current_umn_session.valid_token?(cookies[self.umn_auth_options[:token_name]]) &&
      !current_umn_session.expired?(self.umn_auth_options[:hours_until_cookie_expires])
    ) 
  end
  
  def authorized_by_validation_level?
    current_umn_session.validation_level >= self.umn_auth_options[:validation_level]
  end
  
  def build_umn_session_from_cookie
    x500_response = UmnAuth.development_mode ? development_mode_x500_response : perform_https_request_to_x500_validation_server
    session[:umn_auth] = UmnAuth::Session.new(x500_response, cookies[self.umn_auth_options[:token_name]])
    umn_auth_log "Contents of session[:umn_auth]: #{session[:umn_auth].inspect}"
    return current_umn_session
  end
  
  def perform_https_request_to_x500_validation_server(debug_encrypted_cookie_value_string=nil)
    umn_auth_log "Authentication token in #{self.umn_auth_options[:token_name]} cookie: #{cookies[self.umn_auth_options[:token_name]]}"
    str = debug_encrypted_cookie_value_string ? debug_encrypted_cookie_value_string : cookies[self.umn_auth_options[:token_name]]
    retval = ''
    http = Net::HTTP.new(self.umn_auth_options[:x500_server], self.umn_auth_options[:x500_https_port])
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.use_ssl = true
    validation_uri = "/#{self.umn_auth_options[:validation_module]}?x&#{CGI.escape(str)}"
    http.start { |http| retval = http.request( Net::HTTP::Get.new( validation_uri ) ).body.strip }
    umn_auth_log "Response from server: #{retval}"
    retval
  end
  
  def destroy_umn_session
    session[:umn_auth] = nil
  end
  
  def umn_auth_log(str)
    logger.info("[#{self.umn_auth_options[:name]}] #{str}") if self.umn_auth_options[:logging_enabled]
  end
end