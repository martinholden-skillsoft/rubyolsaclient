#!/usr/bin/env ruby

require 'rexml/document'
include REXML


require 'openid'

require 'openssl'
require 'base64'
include OpenSSL
include Digest

require 'net/http'
require 'net/https'

class OlsaClient

  NAMESPACE= "http://www.skillsoft.com/services/olsa_v1_0/"
  DELIMITER = "_"
  SUFFIX = "Request"

  NONCE_CHRS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0"
  SOAP_ENV_BODY = "/soapenv:Envelope/soapenv:Body"
  SOAP_EXCEPTION_NAME = "/soapenv:Envelope/soapenv:Body/soapenv:Fault/detail/ns2:exceptionName"

  attr_reader :debug
  attr_writer :debug
  
  # Constructor
  #
  # customer_id: OLSA customer id
  # shared_secret: OLSA shared secret
  # endpoint: OLSA endpoint URL
  def initialize(customer_id, shared_secret, endpoint)
    @customer_id = customer_id
    @shared_secret = shared_secret
    @endpoint = endpoint
    @debug = true
  end
  
  # Invoke specified operation with supplied request arguments
  #
  # operation_name: OLSA Web Service operation name
  # request: hash of request arguments (follow spelling and case for the respectice request type from OLSA WSDL), empty hash may be specified
  # value_name: xpath of value to extract (if nil specified then return root of raw response, SOAP_BODY_ENV will prefixed automatically)
  # need_doc: true or false
  #
  # returns
  #   if need_doc then array containing:
  #     - text value for specified xpath (may be nil)
  #     - XML document for response
  #  else
  #     - text value for specified xpath (may be nil)
  #
  # exceptions raised if specified xpath cannout be found
  def invoke(operation_name, request, value_name, need_doc=false)
    response = invoke_direct(operation_name,  request)
    doc = Document.new response
    x = XPath.first( doc, value_name.nil? ? nil : SOAP_ENV_BODY + value_name)
    if x.nil?
      make_exception(doc)
    else
      if need_doc
        if(x.class==Element)
          return x.text, doc
        else
          return x.value, doc
        end
      else
        if(x.class==Element)
          return x.text
        else
          return x.value
        end
      end
    end
  end
  
  # Invoke specified operation with supplied request arguments
  #
  # operation_name: OLSA Web Service operation name
  # request: hash of request arguments (follow spelling and case for the respectice request type from OLSA WSDL)
  #
  # returns response as XML string (including faults)
  # exceptions returned as nil
  def invoke_direct(operation_name, request)
    soap_envelope = make_soap(operation_name, request)
    resp, data = http_post(operation_name, soap_envelope)

    resp::body
      
    rescue => exception
      puts "OLSA invocation FAILED : #{operation_name}\n"
      puts "Exception : " << exception
      puts caller
      return "<_olsa_invocation_exception><![CDATA[ #{operation_name} endpoint=#{@endpoint} exception=#{exception} ]]></_olsa_invocation_exception>"
  end

  # override to_s method (aka toString())
  def to_s
    "OlsaClient: #@customer_id--#@endpoint"
  end


  def make_soap(operation_name, request)
    #http://openidenabled.com/
    nonce = OpenID::CryptUtil::random_string(8, NONCE_CHRS)
	#puts "nonce=#{nonce}"
 
    # ISO 8601 format
    t0 = Time.now
    t1 = t0 + (5 * 60)
    created_time = t0.getutc.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_time = t1.getutc.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # http://www.oasis-open.org/committees/download.php/16782/wss-v1.1-spec-os-UsernameTokenProfile.pdf
    #      Password_Digest = Base64 ( SHA-1 ( nonce + created + password ) )
    # Ruby verion found here: http://www.ruby-forum.com/topic/55706#new
    stamp = Base64::decode64(nonce)+created_time+@shared_secret
    digester = SHA1.new
    digester.update(stamp)
    password_digest = Base64.encode64(digester.digest().strip()).chomp
	#puts "password_digest=#{password_digest}"

    evp = Element.new("soapenv:Envelope")
    evp.attributes["xmlns:soapenv"] = "http://schemas.xmlsoap.org/soap/envelope/"
    evp.attributes["xmlns:xsd"] = "http://www.w3.org/2001/XMLSchema"
    evp.attributes["xmlns:xsi"] = "http://www.w3.org/2001/XMLSchema-instance"
    
    hdr = evp.add_element("soapenv:Header")
    
    sec = hdr.add_element("wsse:Security")
    sec.attributes["xmlns:wsse"] = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    sec.attributes["soapenv:mustUnderstand"] = "1"
    
    ts = sec.add_element("wsu:Timestamp")
    ts.attributes["xmlns:wsu"] = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    ts_cr = ts.add_element("wsu:Created")
    ts_cr.add_text(created_time)
    ts_ex = ts.add_element("wsu:Expires")
    ts_ex.add_text(expires_time)

    ut = sec.add_element("wsse:UsernameToken")
    ut.attributes["xmlns:wsu"] = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    ut_un = ut.add_element("wsse:Username")
    ut_un.add_text(@customer_id)
    ut_pw = ut.add_element("wsse:Password")
    ut_pw.attributes["Type"] = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
    ut_pw.add_text(password_digest)
    ut_nc = ut.add_element("wsse:Nonce")
    ut_nc.add_text(nonce)
    ut_cr = ut.add_element("wsu:Created")
    ut_cr.add_text(created_time)
    
    bdy = evp.add_element("soapenv:Body")
    
    payload = compute_payload_xml(operation_name, request)
    
    bdy.add_element(payload)
    
    return evp
  end

  def http_post(operation_name, body)
    
    uri = URI.parse(@endpoint)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    
    headers = {
      'Accept' => "application/soap+xml, application/dime, multipart/related, text/*",
      'soapaction' => compute_action_header(operation_name),
      'Content-Type' => 'text/xml; charset=utf-8',
      'User-Agent' => 'Axis2C/1.4.0',
       'Cache-Control' => 'no-cache',
       'Pragma' => 'no-cache'  }
  

    resp, data = http.post(uri.path, body.to_s, headers ) 
    return resp, data
  
  end

  # ****************** PRIVATE ******************
  private


  # Compute the XML for the payload to embed in the SOAP body.
  #
  # Given:
  #
  #      "XYZ_Foo", {"a"=>1, "b"=>2, "c"=>3}
  #
  # Compute:
  #
  # <FooRequest xmlns="http://www.skillsoft.com/services/olsa_v1_0/">
  #   <customerId>...</customerId>
  #   <a>1</a> <b>2</b> <c>3</c>
  #</FooRequest>
  #
  # operation_name: OLSA Web Service operation name
  # request: hash of request arguments (follow spelling and case for the respectice request type from OLSA WSDL)
  #
  # returns XML document
  def compute_payload_xml(operation_name, request)
    root = Element.new(compute_request_tag(operation_name))
    root.attributes["xmlns"] = NAMESPACE
    tmp = root.add_element("customerId")
    tmp.add_text(@customer_id)
    compute_payload_xml2(root, request)
  end


  def XYZcompute_payload_xml(operation_name, request)
    req_payload = <<XML
  <GetMultiActionSignOnUrlRequest xmlns="http://www.skillsoft.com/services/olsa_v1_0/">
    <customerId>spxerceoows</customerId>
    <userName>admin</userName>
    <actionType>launch</actionType>
    <assetId>COMM0606</assetId>    
  </GetMultiActionSignOnUrlRequest>
XML
    
    req_payload
  end
  
  # Workhorse method for building elements under the outermost tag.
  # This can handle nested hash arrays. A key will turn into a tag name. The respective value
  # will turn into the text value for the tag.
  #
  # tempRoot - current position in XML document being built
  # request - current hash array to convert
  #
  # returns XML document
  def compute_payload_xml2(tempRoot, request)
    request.each {|key, value| 
      tmp = tempRoot.add_element(key)
      if value.is_a?(Hash)
        compute_payload_xml2(tmp, value)
      else
        tmp.add_text(value.to_s)
      end
    }
    tempRoot
  end

  def compute_action_header(operation_name)
    NAMESPACE + operation_name
  end


  # Compute the name of the outermost payload tag from the OLSA
  # Web Service operation name.
  #
  # For example, turn SO_GetMultiActionSignOnUrl into GetMultiActionSignOnUrlRequest
  def compute_request_tag(operation_name)
    operation_name.sub(Regexp.new(".*#{DELIMITER}"),'') + SUFFIX
  end

  # Only call this if a valid response cannot be extracted from 'doc'
  #
  # doc - XML document returned by OLSA call
  #
  # No return value, this will always raise some form of an exception
  def make_exception(doc)
    node = XPath.first(doc, SOAP_EXCEPTION_NAME)
    unless node.nil?
      case node.text
        when /.*\.GeneralFault$/
          raise GeneralFault, doc.to_s, caller
        when /.*\.ObjectNotFoundFault$/
          raise ObjectNotFoundFault, doc.to_s, caller
        when /.*\.ObjectExistsFault$/
          raise ObjectExistsFault, doc.to_s, caller
        when /.*\.RequestAlreadyInProgressFault$/
          raise RequestAlreadyInProgressFault, doc.to_s, caller
        when /.*\.DataNotReadyYetFault$/
          raise DataNotReadyYetFault, doc.to_s, caller
        when /.*\.MentoringNotEnabledFault$/
          raise MentoringNotEnabledFault, doc.to_s, caller
        when /.*\.NoResultsAvailableFault$/
          raise NoResultsAvailableFault, doc.to_s, caller
        when /.*\.DownloadNotEnabledFault$/
          raise DownloadNotEnabledFault, doc.to_s, caller
        when /.*\.(ReportDoesNotExistFault)$/
#          puts "$1=#{$1} $2=#{$2}"
          raise ReportDoesNotExistFault, doc.to_s, caller
      else
          # unrecognized SOAP fault
          raise Exception, doc.to_s, caller
        end
    else
      # unknown response
      raise Exception, doc.to_s, caller
    end
  end
  
  def get_reason_text(exception)
     doc = Document.new exception.to_s
     node = XPath.first(doc, "/soapenv:Fault/soapenv:Reason/soapenv:Text")
   unless node.nil?
      node.text
    else
      "no reason could be found"  
    end
  end
  
end

# define known OLSA faults here

class GeneralFault < Exception
end

class ObjectNotFoundFault < GeneralFault
end

class ObjectExistsFault < GeneralFault
end

class RequestAlreadyInProgressFault < GeneralFault
end

class DataNotReadyYetFault < GeneralFault
end

class MentoringNotEnabledFault < GeneralFault
end

class NoResultsAvailableFault < GeneralFault
end

class DownloadNotEnabledFault < GeneralFault
end

class ReportDoesNotExistFault < GeneralFault
end
