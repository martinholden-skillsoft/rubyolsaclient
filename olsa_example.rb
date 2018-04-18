
require_relative 'olsaclient'

begin
	print "Enter Skillsoft Olsa Site (i.e. evaltls01.skillwsa.com) "
	host = gets.chomp
	fullhost = "https://"+host+"/olsa/services/Olsa"
	
	print "Enter customerid "
	customerid = gets.chomp
	
	print "Enter sharedsecret "
	sharedsecret = gets.chomp
	
	olsa_client = OlsaClient.new(customerid, sharedsecret, fullhost)
	
	#The XPATH statement to extract a value from the OLSA Response
	#We are calling the the UM_GetUserDetailsExtended function https://documentation.skillsoft.com/en_us/skillport/8_0/olsa/index.htm#50455.htm
	#And we will extract the regDate value.
	olsaxpath = "/GetUserDetailsExtendedResponse/user/@regDate"

	#Invoke Olsa Command
	value, response = olsa_client.invoke("UM_GetUserDetailsExtended",  {"username" => "olsa_admin"}, olsaxpath, true)

	# Compact uses as little whitespace as possible, dump the response
	#formatter = REXML::Formatters::Pretty.new
	#formatter.compact = true
	#formatter.write(response, $stdout)

	puts
	puts "Response: "+ String(response)
	puts
	puts "XPATH: " + String(olsaxpath) + " Value: " +String(value)


	rescue GeneralFault => x
		puts "Caught " + x.class.to_s + ": " + x.to_s

end