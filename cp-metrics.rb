require 'log4r'
require 'rest-client'
require 'base64'
require 'json'
require 'time'
require_relative 'Settings'

# Logger
$log = Log4r::Logger.new 'cp-metrics'
$log.outputters = Log4r::Outputter.stdout
$log.level = Log4r::DEBUG

rc_log = Log4r::Logger.new 'rest-client'
rc_log.outputters = Log4r::Outputter.stdout
rc_log.level = Log4r::DEBUG
RestClient.log = rc_log.debug


$metrics = []

def send_events
  json = api("events")
  events = json["events"]

  $log.info "Pulled #{events.count} events."

  s = TCPSocket.open("cp.threatboundary.org", 2003)
  s.write("events.all #{events.count} #{Time.now.to_i}\n")
  s.close

  events
end

def send_servers
  json = api("servers")
  servers = json["servers"]
  $log.info "Pulled #{servers.count} servers."

  metrics 



  s = TCPSocket.open("cp.threatboundary.org", 2003)
  s.write("servers.all #{servers.count} #{Time.now.to_i}\n")
  s.close

  servers
end

def send_configuration_policies
  json = api("policies")
  policies = json["policies"]

  $log.info "Pulled #{policies.count} configuration policies."

  s = TCPSocket.open("cp.threatboundary.org", 2003)
  s.write("policies.configuration.all #{policies.count} #{Time.now.to_i}\n")
  s.close

  policies
end

def send_firewall_policies
  json = api("firewall_policies")
  policies = json["firewall_policies"]

  $log.info "Pulled #{policies.count} firewall policies."

  s = TCPSocket.open("cp.threatboundary.org", 2003)
  s.write("policies.firewall.all #{policies.count} #{Time.now.to_i}\n")
  s.close

  policies
end

def send_users
  json = api("users")
  users = json["users"]

  $log.info "Pulled #{users.count} cloud passage users."

  s = TCPSocket.open("cp.threatboundary.org", 2003)
  s.write("users.all #{users.count} #{Time.now.to_i}\n")
  s.close

  users
end

def send_server_groups
  json = api("groups")
  groups = json["groups"]

  $log.info "Pulled #{groups.count} server groups."

  s = TCPSocket.open("cp.threatboundary.org", 2003)
  s.write("groups.all #{groups.count} #{Time.now.to_i}\n")
  s.close

  groups
end

def send_metrics
  $log.info "Sending #{metrics.count} metrics to #{Settings.graphite}."

  s = TCPSocket.open(Settings.graphite, 2003)

  $metrics.each { |metric|
    s.write "#{metric[:label]} #{metric[:value]} #{metric[:time]}"
  }

  s.close
end 

def authenticate
  uri = "https://#{Settings.key}:#{Settings.secret}@api.cloudpassage.com/oauth/access_token?grant_type=client_credentials"

  begin
    response = RestClient.post uri, :params => "noop"
  rescue => e
    $log.error "Error authenticating to grid."
    $log.error e.to_s
    exit 1
  end

  json = JSON.parse(response)
  $token = json["access_token"]
  $token_expires = Time.now + json["expires_in"]
  $token_read_only = json["scope"] == "read"

  $log.debug ("Token: #{$token}")

  scope = json["scope"]
  expires = json["expires_in"]
  $log.info "Retrieved #{scope} token valid for #{expires} seconds."
end


def api(resource)
  uri = Settings.endpoint + resource

  if Time.now > $token_expires
    $log.debug "Token expired, reauthenticating."
    authenticate
  end

  $log.debug ("Performing api call to: #{uri}")

  begin
    response = RestClient.get uri, :Authorization => "Bearer #{$token}", :accept => :json
  rescue => e
    $log.error "Error hitting Halo API"
    $log.error e.to_s
    exit 1
  end

  json = JSON.parse(response)
end


# 
# => Start execution
#
authenticate




events   = send_events
servers  = send_servers
configuration_policies = send_configuration_policies
firwall_policies = send_firewall_policies
users = send_users
groups = send_server_groups

send_metrics