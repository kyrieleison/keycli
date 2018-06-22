require 'openssl'
require 'base64'

TAG = 'keycli'

class Key
  def initialize
    @key = OpenSSL::PKey::EC.new('prime256v1')
    @key.generate_key
    %x(echo "#{@key.to_pem}" > private_key)
    %x(openssl ec -in private_key -pubout -out public_key > /dev/null 2>&1)
  end

  def private_key
    @key.to_pem
  end

  def out_private_key
    escape(private_key)
  end

  def public_key
    %x(cat public_key)
  end

  def out_public_key
    escape(public_key)
  end

  def sign(challenge)
    binary = @key.dsa_sign_asn1(Digest::SHA256.digest(challenge))
    Base64.strict_encode64(binary)
  end

  def delete
    %x(rm -f private_key public_key)
  end

  private

  def escape(key)
    key.gsub(/(\r\n|\r|\n)/, '\\\\n')
  end
end

key = Key.new

puts 'Public Key: '
puts key.out_public_key
puts

puts 'Available Command: '
puts "  private_key \tOutput the private key."
puts "  public_key  \tOutput the public key."
puts "  sign    \tGenerate signature for challenge."
puts "  copy    \tCopy one of private_key or public_key to the clipboard."
puts

while true
  begin
    print "#{TAG}> "
    input = gets.chomp

    next if input.empty?

    case input
    when 'private_key' then
      puts key.out_private_key
    when 'public_key' then
      puts key.out_public_key
    when 'sign' then
      print 'what\'s challenge?: '
      challenge = gets.chomp
      puts key.sign(challenge)
    when 'copy' then
      print 'what to copy? (private_key|public_key): '
      subinput = gets.chomp
      value = key.send(subinput)
      %x(echo '#{value.gsub(/(\r\n|\r|\n)/, '\\\\\\n')}' | pbcopy)
      puts "#{subinput} is copied!"
    when 'exit' then
      key.delete
      puts 'bye'
      break
    else
      puts "command not found: #{input}"
    end
  rescue Interrupt => e
    key.delete
    raise e
  end
end
