# UmnAuth #

UmnAuth is an authentication plugin for Rails. This enables cookie-based authentication of users to the University of Minnesota's X500 server.

## Installation

* Using Rails 2.1.* :

<pre>
./script/plugin install git://github.com/jfernandez/umn_authentication_filter.git
</pre>

* Using Rails 2.0.* :

<pre>
cd vendor/plugins
git clone git@github.com:jfernandez/umn_authentication_filter.git umn_auth
cd umn_auth
ruby install.rb
</pre>

* If you're using Subversion, you can download the tarball and unzip it to your /vendor/plugins directory.  Then run `ruby install.rb` from the plugin root folder.

* If the install.rb script wasn't able to copy over the `umn_auth_users.yml` file into your RAILS_ROOT/config directory, then manually copy over the template from the plugin directory.  Use this config yaml file to set the mocked users to be used while in development mode.

* Include the plugin in your Application controller (`application.rb`) :

<pre>
class ApplicationController < ActionController::Base
   include UmnAuth
end
   
</pre>

* If you wish to enable the development mode, add the following lines to your development environment (`development.rb`) :

<pre>
UmnAuth.development_mode = true
UmnAuth.development_mode_current_user = 'foo' # optional, set to 'gopher' by default
</pre>

Optionally, you can set `UmnAuth.development_mode_current_user` to one of the mocked users in your yaml config file.

## Instructions

UmnAuth provides you the `umn_auth_required` method, which can be used as a before_filter in any of your application's controllers.  This method will redirect the user to the University of Minnesota X500 login page if no authentication cookie is found. The `umn_auth_required` filter implements the requirements and guidelines found at the UMN Central Authentication Hub website (http://www1.umn.edu/is/cookieauth/aboutcah.html).  The filter will only allow the execution of the controller code once the user has been successfully authenticated with the X500 server.

<pre>
class ExamsController < ApplicationController

  before_filter :umn_auth_required

  def show
   # Private stuff
  end

end
</pre>

Once authenticated, UmnAuth stores the user's UmnAuth::Session in session[:umn_auth].  UmnAuth::Session has the following attributes:

* validation_level
* timestamp
* ip_address
* internet_id

The current UmnAuth::Session can be easily accessed in a controller or view using the `current_umn_session` method.

<pre>
class ExamsController < ApplicationController

  before_filter :umn_auth_required

  def show
   @user_name = current_umn_session.internet_id
  end

end
</pre>

<pre>
...
<h1>Hello <%= current_umn_session.internet_id %>!</h1>   
...
</pre>
