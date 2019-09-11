# frozen_string_literal: true

module PayboxSystem
  module Rails
    module Helpers
      # Add all formatted params as hidden fields
      def paybox_hidden_field_tags(opts = {})
        formatted_params = PayboxSystem.formatted_params(opts)
        capture do
          formatted_params.each do |name, value|
            value = Rack::Utils.escape(value) if name != 'PBX_PORTEUR'
            concat hidden_field_tag(name, value)
          end
        end
      end
    end
  end
end
