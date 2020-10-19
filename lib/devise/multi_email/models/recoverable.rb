require 'devise/multi_email/parent_model_extensions'

module Devise
  module Models
    module EmailRecoverable
      extend ActiveSupport::Concern

      included do
        devise :recoverable

        include RecoverableExtensions
      end

      module RecoverableExtensions
      end
    end

    module MultiEmailRecoverable
      extend ActiveSupport::Concern

      included do
        include Devise::MultiEmail::ParentModelExtensions

        devise :recoverable

        include RecoverableExtensions
      end

      module RecoverableExtensions
        extend ActiveSupport::Concern

        included do
          multi_email_association.include_module(EmailRecoverable)
        end

      protected

      private

        module ClassMethods
          #delegate :send_reset_password_instructions

          def send_reset_password_instructions(attributes={})
            recoverables = find_or_initialize_with_errors([:address], {
                  address: attributes.delete(:email)
                }, :not_found)
            recoverables[0].send_reset_password_instructions if recoverables[0] and recoverables[0].persisted?
            recoverables[0]
          end

        end
      end
    end
  end
end
