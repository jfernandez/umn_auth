# UmnAuth #

UmnAuth is an authentication plugin for Rails. This enables cookie-based authentication of users to the University of Minnesota's X500 server.

## Installation

    ./script/plugin install git://github.com/jfernandez/umn_auth.git

1. If you're using Subversion, you can download the tarball and unzip it to your /vendor/plugins directory.  Then run `ruby install.rb` from the plugin root folder.

2. If the install.rb script wasn't able to copy over the `umn_auth_users.yml` file into your RAILS_ROOT/config directory, then manually copy over the template from the plugin directory.  Use this config yaml file to set the mocked users to be used while in development mode.

3. Include the plugin in your Application controller (`application.rb`) :

4. If you wish to enable the development mode, add the following lines to your development environment (`development.rb`) :

`UmnAuth.development_mode = true`
`UmnAuth.development_mode_current_user = 'foo' # optional, set to 'gopher' by default`

Optionally, you can set `UmnAuth.development_mode_current_user` to one of the mocked users in your yaml config file.

## Instructions

UmnAuth provides you the `umn_auth_required` method, which can be used as a before_filter in any of your application's controllers.  This method will redirect the user to the University of Minnesota X500 login page if no authentication cookie is found. The `umn_auth_required` filter implements the requirements and guidelines found at the UMN Central Authentication Hub website (http://www1.umn.edu/is/cookieauth/aboutcah.html).  The filter will only allow the execution of the controller code once the user has been successfully authenticated with the X500 server.

    class ExamsController < ApplicationController

      before_filter :umn_auth_required

      def index
       # Private stuff
      end

    end

Once authenticated, UmnAuth stores the user's UmnAuth::Session in `session[:umn_auth]`.  UmnAuth::Session has the following attributes:

* validation_level
* timestamp
* ip_address
* internet_id

The current UmnAuth::Session can be easily accessed in any controller or view using the `current_umn_session` method.

    class ExamsController < ApplicationController

      before_filter :umn_auth_required

      def index
       @exams = Exam.find_by_internet_id(current_umn_session.internet_id)
      end

    end

---
Written by Jose Fernandez and Zachary Crockett<br/>
Acknowledgements: Trevor Wennblom, Justin Coyne, Joe Goggins, Christopher Warren