Paybox System for Ruby
======================

[![Build Status](https://secure.travis-ci.org/slainer68/paybox_system.png?branch=master)](http://travis-ci.org/slainer68/paybox_system)

Introduction
------------

This gem is the Ruby implementation of the e-commerce payment gateway Paybox System from [Paybox](http://www.paybox.com).

This gem is unofficial and is not approved or endorsed by Paybox System.

Please note that Paybox provides several solutions. Depending of the solution you have chosen, you must use different implementations.

In my humble opinion :

* For Paybox Direct, use ActiveMerchant and the built-in Paybox Direct gateway
* For Paybox Direct Plus, use ActiveMerchant and use the Paybox Direct Plus gateway provided [here](https://github.com/arambert/Paybox-Direct-Plus)
* For Paybox System, use this gem.

IMPORTANT! The default way of using Paybox System is by sending commands to a CGI module.
The problem with the CGI is that you have to use the good CGI depending on your architecture, if you upgrade your architecture it may breaks, and moreover on some cloud architecture like Heroku, you are just not allowed to run CGIs...

Paybox provides also a way to use Paybox System without CGI. This gem use this method, so you can safely use it on any architecture.

I highly recommend you to contact Paybox by email and tell them you want to use "Paybox System without CGI by calculating the HMAC yourself".

Paybox System Basics
--------------------

(Do not read this paragraph if you already know how Paybox System works)

I recommend you to read the Paybox System manual. Please contact Paybox and ask them the PDF manual for "Paybox System without CGI".

Basically you have to create a HTML form containing some hidden fields. Those fields contains the parameters you have to send to Paybox like your identification, the amount of the transaction, etc.

The last field contains a cryptographic signature. This signature has to be generated from all the previous fields using a secret key. You can generate the secret key in the administration interface provided by Paybox.

The signature is used by Paybox to validate that the form has been generated by you and has not been modified by anybody.

When the user submits the form, it is redirected to Paybox where the payment is eventually made.

When the payment is made, Paybox sends a callback to your site (Instant Payment Notification) and the user is redirected back to your site.

When the callback and redirections are made, Paybox sends you a signature in the parameters. You have to verify the signature using the Paybox public cryptographic key (RSA) to be sure that the request has been made by Paybox.

How to use this gem
-------------------

This gem only depends on the built-in OpenSSL Ruby libs and Rack. You can use it with any Ruby web framework.

The gem consists of 2 main methods : one to build the parameters you have to send to Paybox, the other to check the integrity of the Paybox response.

Configuration
-------------

You must initialize a configuration Hash before using the main Base class methods.
This configuration Hash must at least contain the secret key in the key :secret_key.

For example, the test secret key :

    Paybox::System::Base.config = { :secret_key => "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" }

Building the Paybox parameters
------------------------------

Check the manual for the complete list of all the different parameters you need to send to Paybox.
All these parameters are upper-case and begin by `PBX_`, like : `PBX_SITE`.
Use the `Paybox::System::Base.hash_form_fields_from` with a hash that contains all the paybox parameters in symbols without `PBX_`, for example :

     Paybox::System::Base.hash_form_fields_from(:site => "XYZ") # => returns { "PBX_SITE" => "XYZ", etc. }

The returning Hash also contains 3 additional keys : `PBX_HASH` that is always `SHA512`, `PBX_TIME` with the current timestamp (so you don't have to calculate it yourself) and more important, it contains the signature in `PBX_HMAC` based on all the previous parameters and the secret key.

Real example with the Paybox test parameters :

    Paybox::System::Base.hash_form_fields_from(:site => "1999888", :rang: "32", :identifiant: "107904482",
                                               :paybox => "https://preprod-tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi",
                                               :backup1 => "https://preprod-tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi",
                                               :backup2 => "https://preprod-tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi",
                                               :total => "1500",
                                               :devise => 978,
                                               :cmd => "id cmd 123456",
                                               :porteur => "test@paybox.com",
                                               :retour => "amount:M;reference:R;autorization:A;error:E;sign:K",
                                               :effectue => "http://monsite.com/payment_success",
                                               :refuse => "http://monsite.com/payment_refused",
                                               :annule => "http://monsite.com/payment_canceled",
                                               :repondre_a => "http://monsite.com/payment_callback")

Use the returned Hash to build the form.

Verifying the Paybox Response
-----------------------------

When Paybox redirects the user back to your site or makes the callback, you have to check that the request comes from Paybox.
Otherwise anybody can send a manually-made request to your server.
To do so, you have to verify the signature provided by Paybox in the request.

You have to get the full request path and separate the parameters and the signature.
Then use the `Paybox::System::Base.check_response?` with the parameters string and the signature.
If the method returns true, the message integrity is verified, otherwise there is a problem and you should raise an exception.

For example :

    http://mysite.com/payment_callback?amount=1500&error=00000&reference=id123456&sign=ABCDEFGH123456

    => The parameters string is : "amount=1500&error=00000&reference=id123456"
    => The signature string is : "ABCDEFGH123456"

    => Paybox::System::Base.check_response?("amount=1500&error=00000&reference=id123456", "ABCDEFGH123456")

Rails helpers
-------------

If you use Rails 3, you don't have to directly use the Base methods.
This gem provides a helper class that contains a view helper to generate the form and a before\_filter to use in controllers to check the integrity of the Paybox response.

Create an initializer `config/initializers/paybox_system.rb`:

    require "paybox_system/rails/helpers"
    Paybox::System::Base.config = { secret_key => "YOUR_SECRET_KEY" } # I recommend you to load the key depending of the environment! Connect to the Paybox administration interface to generate the key (see the manual)

In the view Helper you want to create a paybox form, add:

    include Paybox::System::Rails::Helpers


Then use the `paybox_hidden_fields` helper with the same Hash you may use with the `hash_form_fields_from` method (bellow).

Example of the view:

        <form method="POST" action="https://preprod-tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi">
          <%= paybox_hidden_fields :site => "ABCDEFG", :rang => "01" # , ... See bellow for the Hash you have to create %>
        </form>

IMPORTANT! I recommend you to create the form HTML tags in pure HTML and not use form\_tag or form\_for Rails helpers as Paybox will not like the additional fields that Rails adds with these helpers.

In the controller(s) that contains the action(s) called by Paybox (for example : when a payment is made (IPN) or canceled), to check the integrity of the response, use the `check_paybox_integrity!` before\_filter provided by the module `Paybox::System::Rails::Integrity`.

    class PurchasedProductsController < ApplicationController
      include Paybox::System::Rails::Integrity

      before_filter :check_paybox_integrity!

      def ipn
        if params[:error] == "00000"
          # Yipee, the payment is confirmed!
          # ...
        end

        render :text => "OK"
      end
    end

IMPORTANT! To use the `check_paybox_integrity!` before\_filter you have to tell Paybox to append the signature in a parameter called `sign`.

So the `PBX_RETOUR` parameter (`:retour` key in the Hash) must finish by : `sign:K`.
See the official manual for more information on the `PBX_RETOUR` variable.
For example, you may use : `:retour => "amount:M;reference:R;autorization:A;error:E;sign:K"` in the form fields generation method.

Contributing to Paybox System for Ruby
--------------------------------------
 
* Check out the latest master to make sure the feature hasn't been implemented or the bug hasn't been fixed yet.
* Check out the issue tracker to make sure someone already hasn't requested it and/or contributed it.
* Fork the project.
* Start a feature/bugfix branch.
* Commit and push until you are happy with your contribution.
* Make sure to add tests for it. This is important so I don't break it in a future version unintentionally.
* Please try not to mess with the Rakefile, version, or history. If you want to have your own version, or is otherwise necessary, that is fine, but please isolate to its own commit so I can cherry-pick around it.

Copyright
---------

Copyright (c) 2012 Nicolas Blanco & Keley Consulting. See LICENSE.txt for further details.
