require 'devise/multi_email/parent_model_extensions'

module Devise
  module Models
    module EmailAuthenticatable
      def devise_scope
        self.class.multi_email_association.model_class
      end
    end

    module MultiEmailAuthenticatable
      extend ActiveSupport::Concern

      included do
        include Devise::MultiEmail::ParentModelExtensions

        attr_accessor :current_login_email

        devise :database_authenticatable

        include AuthenticatableExtensions
      end

      def self.required_fields(klass)
        []
      end

      module AuthenticatableExtensions
        extend ActiveSupport::Concern

        included do
          multi_email_association.configure_autosave!{ include AuthenticatableAutosaveExtensions }
          multi_email_association.include_module(EmailAuthenticatable)
        end

        delegate :skip_confirmation!, to: Devise::MultiEmail.primary_email_method_name, allow_nil: false

        # Gets the primary email address of the user.
        def email
          multi_email.primary_email_record.try(:address)
        end

        # Sets the default email address of the user.
        def email=(new_email)
          multi_email.change_primary_email_to(new_email, allow_unconfirmed: true)
        end
      end

      module AuthenticatableAutosaveExtensions
        extend ActiveSupport::Concern

        included do
          # Toggle `primary` value for all emails if `autosave` is not on
          after_save do
            multi_email.filtered_emails.each do |email|
              # update value in database without persisting any other changes
              email.save if email.changes.key?(:primary)
            end
          end
        end
      end

      module ClassMethods
        def find_or_initialize_with_errors(required_attributes, attributes, error=:invalid) #:nodoc:
          attributes.try(:permit!)
          attributes = attributes.to_h.with_indifferent_access
                                 .slice(*required_attributes)
                                 .delete_if { |key, value| value.blank? }

          if attributes.size == required_attributes.size
            records = find_first_by_auth_conditions(attributes) #and return records
            if records[0] and !records[0].nil?
                return records
            end
          end

          corrected_attributes = attributes
          if corrected_attributes.has_key?(:address)
            corrected_attributes[:email] = corrected_attributes.delete(:address)
          end
          resource_with_errors = new(devise_parameter_filter.filter(corrected_attributes)).tap do |record|
            [:email].each do |key| #required_attributes.each do |key|
              record.errors.add(key, attributes[key].blank? ? :blank : error)
            end
          end

          return resource_with_errors, nil
        end


        def find_first_by_auth_conditions(tainted_conditions, opts = {})
          filtered_conditions = devise_parameter_filter.filter(tainted_conditions.dup)
          criteria = filtered_conditions.extract!(:address, :unconfirmed_email, :confirmation_token, :reset_password_token)

          if criteria.keys.any?
            conditions = filtered_conditions.to_h.merge(opts).
              reverse_merge(criteria) #build_conditions(criteria))

            # Make this work both ways because we may be looking for the user
            #    account versus the email (like when we want to reset a pass.
            if (multi_email_association.name.to_s.classify.constantize).column_names.include? filtered_conditions.to_h.merge(opts).reverse_merge(criteria).first[0].to_s
              true_confirmable_resource = (multi_email_association.name.to_s.classify.constantize).find_by(conditions)
              primary_resource = true_confirmable_resource.nil? ? nil :
                true_confirmable_resource.user
              primary_resource.current_login_email = criteria.values.first if primary_resource
            else
              true_confirmable_resource = (Devise.default_scope.to_s.classify.constantize).find_by(conditions)
              primary_resource = true_confirmable_resource
            end
            return primary_resource, true_confirmable_resource
          else
            return nil, nil
          end
        end

        def find_by_email(email)
          joins(multi_email_association.name).where(build_conditions address: email).first
        end

        def build_conditions(criteria)
          criteria = devise_parameter_filter.filter(criteria)
          # match the primary email record if the `unconfirmed_email` column is specified
          if Devise::MultiEmail.only_login_with_primary_email? || criteria[:unconfirmed_email]
            criteria.merge!(primary: true)
          end

          { multi_email_association.reflection.table_name.to_sym => criteria }
        end
      end
    end
  end
end
