module UmnAuth
  module Authenticated
    
    def self.included(base)
      base.extend ActMethods 
    end
    
    module ActMethods
      
      def acts_as_umn_authenticated
        unless included_modules.include? InstanceMethods 
          extend ClassMethods
          include InstanceMethods
        end
      end
      
      module ClassMethods
      end
      
      module InstanceMethods
      end      
      
    end
    
  end
end