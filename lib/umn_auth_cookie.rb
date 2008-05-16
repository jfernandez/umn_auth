class UMNAuthCookie
  attr_reader :validation_level, :timestamp, :ip_address, :internet_id
  
  def initialize( str )
    unless str[0..2] == "OK:"
      raise IndexError, "UMNAuthCookie passed invalid string.  Must start with 'OK:'.  Currently: '#{str.inspect}'"
    end
    fields = str[3..-1].split('|')
    @validation_level = fields[0].to_i
    @timestamp = fields[1].to_i
    @ip_address = fields[2]
    @internet_id = fields[3]
  end

  def authentication_method
    case @validation_level.to_i
    when 5
      "Forced password change - protected web servers must NOT allow access at this level"
    when 10
      "Guest account"
    when 20
      "User initiated their account for the first time"
    when 30
      "Internet password"
    when 40
      "Enterprise password"
    when 50
      "Two-factor"
    else
      "Unknown"
    end
  end
end
