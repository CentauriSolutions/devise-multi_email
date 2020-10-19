require 'devise/multi_email/parent_model_extensions'

module Devise
  module Models
    module EmailConfirmable
      extend ActiveSupport::Concern

      included do
        devise :confirmable

        include ConfirmableExtensions
      end

      module ConfirmableExtensions
        def confirmation_period_valid?
          primary? ? super : false
        end
      end
    end

    module MultiEmailConfirmable
      extend ActiveSupport::Concern

      included do
        include Devise::MultiEmail::ParentModelExtensions

        devise :confirmable

        include ConfirmableExtensions
      end

      def self.required_fields(klass)
        []
      end

      module ConfirmableExtensions
        extend ActiveSupport::Concern

        included do
          multi_email_association.include_module(EmailConfirmable)
        end

        # delegate before creating overriding methods
        delegate :skip_confirmation!, :skip_confirmation_notification!, :skip_reconfirmation!, :confirmation_required?,
                 :confirmation_token, :confirmed_at, :confirmed_at=, :confirmation_sent_at, :confirm, :confirmed?, :unconfirmed_email,
                 :reconfirmation_required?, :pending_reconfirmation?, to: Devise::MultiEmail.primary_email_method_name, allow_nil: true

       def initialize(*args, &block)
          @bypass_confirmation_postpone = false
          @skip_reconfirmation_in_callback = false
          @reconfirmation_required = {}
          @skip_confirmation_notification = false
          @raw_confirmation_token = {}

          begin
            self.email_addresses.each do |a|
              @reconfirmation_required[a.id] = false
              @raw_confirmation_tokens[a.id] = nil
            end
          rescue
          end

          super
        end


        def confirm(args={})
          if args[:address]
            address = args[:address]
            pending_any_confirmation(address) do
              if confirmation_period_expired?(address)
                self.errors.add(:email, :confirmation_period_expired,
                  period: Devise::TimeInflector.time_ago_in_words(self.class.confirm_within.ago))
                return false
              end

              address.confirmed_at = Time.now.utc
              saved = if pending_reconfirmation?(address)
                skip_reconfirmation!(address)
                address.address = unconfirmed_email
                address.unconfirmed_email = nil

                # We need to validate in such cases to enforce e-mail uniqueness
                address.save(validate: true)
              else
                address.save(validate: args[:ensure_valid] == true)
              end

              after_confirmation if saved
              saved
            end
          end
        end


        def confirmed?(address=nil)
          if address.nil?
            false
          else
            !!address.confirmed_at
          end
        end


        def pending_reconfirmation?(address)
          self.class.reconfirmable && address.unconfirmed_email.present?
        end



        # In case email updates are being postponed, don't change anything
        # when the postpone feature tries to switch things back
        def email=(new_email)
          multi_email.change_primary_email_to(new_email, allow_unconfirmed: unconfirmed_access_possible?)
        end

        # This need to be forwarded to the email that the user logged in with
        def active_for_authentication?
          login_email = multi_email.login_email_record

          if login_email && !login_email.primary?
            super && login_email.active_for_authentication?
          else
            super
          end
        end

        # Shows email not confirmed instead of account inactive when the email that user used to login is not confirmed
        def inactive_message
          login_email = multi_email.login_email_record

          if login_email && !login_email.primary? && !login_email.confirmed?
            :unconfirmed
          else
            super
          end
        end

        # If you don't want confirmation to be sent on create, neither a code
        # to be generated, call skip_confirmation!
        def skip_confirmation!(address)
          address.confirmed_at = Time.now.utc
        end


        def send_confirmation_instructions(address)
          unless @raw_confirmation_token
            generate_confirmation_token!(address)
          end

          opts = pending_reconfirmation?(address) ? { to: address.unconfirmed_email } : { to: address.address }
          send_devise_notification(:confirmation_instructions, @raw_confirmation_token, opts)
        end

        def send_reconfirmation_instructions(address)
          @reconfirmation_required[address.id] = false

          unless @skip_confirmation_notification
            send_confirmation_instructions(address)
          end
        end

        def resend_confirmation_instructions(address)
          pending_any_confirmation(address) do
            send_confirmation_instructions(address)
          end
        end


      protected

        # Overrides Devise::Models::Confirmable#postpone_email_change?
        def postpone_email_change?
          false
        end

        # Email should handle the confirmation token.
        def generate_confirmation_token(address=nil)
          if !address.nil?
            if address.confirmation_token && !confirmation_period_expired?(address)
              @raw_confirmation_token = address.confirmation_token
            else
              address.confirmation_token = @raw_confirmation_token = Devise.friendly_token
              address.confirmation_sent_at = Time.now.utc
            end
          end
        end

        def generate_confirmation_token!(address)
          generate_confirmation_token(address) && address.save(validate: false)
        end

        # Email will send reconfirmation instructions.
        def send_reconfirmation_instructions
        end

        # Email will send confirmation instructions.
        def send_on_create_confirmation_instructions
        end

        def confirmation_required?(address=nil)
          if address.nil?
            true
          else
            !confirmed?(address)
          end
        end

        def confirmation_period_valid?(address=nil)
          return true if self.class.allow_unconfirmed_access_for.nil?
          return false if self.class.allow_unconfirmed_access_for == 0.days

          if address.nil?
            true
          else
            address.confirmation_sent_at && address.confirmation_sent_at.utc >= self.class.allow_unconfirmed_access_for.ago
          end
        end


        def confirmation_period_expired?(address=nil)
          if address.nil?
            false
          else
            self.class.confirm_within && address.confirmation_sent_at && (Time.now.utc > address.confirmation_sent_at.utc + self.class.confirm_within)
          end
        end


        def pending_any_confirmation(address)
          if (!address.confirmed? || address.pending_reconfirmation?)
            yield
          else
            self.errors.add(:email, :already_confirmed)
            false
          end
        end

        def reconfirmation_required?(address=nil)
          if address.nil? or @reconfirmation_required.nil?
            true
          else
            self.class.reconfirmable && @reconfirmation_required[address.id] && (address.address.present? || self.unconfirmed_email.present?)
          end
        end


      private

        def unconfirmed_access_possible?
          Devise.allow_unconfirmed_access_for.nil? || \
            Devise.allow_unconfirmed_access_for > 0.days
        end

        module ClassMethods
          delegate :confirm_by_token, :send_confirmation_instructions, to: 'multi_email_association.model_class', allow_nil: false

          def send_confirmation_instructions(attributes={})
            confirmables = find_by_unconfirmed_email_with_errors(attributes) if reconfirmable
            unless confirmables.try(:persisted?)
              if confirmation_keys[0] == :email and attributes.key?("email")
                confirmables = find_or_initialize_with_errors([:address], {
                  address: attributes.delete(:email)
                }, :not_found)
              else
                confirmables = find_or_initialize_with_errors(confirmation_keys, attributes, :not_found)
              end
            end

            if confirmables and confirmables[0]
              if confirmables[0].persisted?
                confirmables[0].resend_confirmation_instructions(
                  confirmables[1]
                ) 
              end
              confirmables[0]
            end
          end

          def confirm_by_token(confirmation_token)
            if confirmation_token.blank?
              confirmable = new
              confirmable.errors.add(:confirmation_token, :blank)
              return confirmable
            end

            confirmables = find_first_by_auth_conditions(confirmation_token: confirmation_token)

            unless confirmables
              confirmation_digest = Devise.token_generator.digest(self, :confirmation_token, confirmation_token)
              confirmables = find_or_initialize_with_error_by(:confirmation_token, confirmation_digest)
            end
            confirmables[0].confirm({ address: confirmables[1] }) if confirmables[1].persisted?
            confirmables[0]
          end


        end
      end
    end
  end
end
