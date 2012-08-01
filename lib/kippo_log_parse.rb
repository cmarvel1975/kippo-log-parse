class Kippo_log_parse
  NEWCONNECTION_REGEX = /\[kippo\.core\.honeypot\.HoneyPotSSHFactory\]\sNew\sconnection\:\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,8}\s\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:22\)\s\[session\:\s(\d*)\]/
  SSHVERSION_REGEX = /\[HoneyPotTransport,\d,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]\s(Remote\sSSH\sversion:\s.*)/
  DISCONNECTION_REGEX = /\[HoneyPotTransport\,(\d{1,8}),(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\sconnection\slost/
  AUTH_ATTEMPT = /\[SSHService\sssh-userauth\son\sHoneyPotTransport,(\d{1,8}),(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s(.*\strying\s.*)/
  LOGIN_ATTEMPT = /\[SSHService\sssh-userauth\son\sHoneyPotTransport,(\d{1,8}),(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\slogin\sattempt\s\[(.*)\/(.*)\]\s(.*)/
  LOGIN_SUCCESS = /\[SSHService\sssh-userauth\son\sHoneyPotTransport,(\d{1,8}),(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s(.*)\sauthenticated\swith\s(.*)/
  CMD_RUN = /\[SSHChannel\ssession\s\(\d{1,8}\)\son\sSSHService\sssh-connection\son\sHoneyPotTransport,(\d{1,8}),(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\sCMD:\s(.*)/

  def parse(line)
    new_connection = line.match(NEWCONNECTION_REGEX)
    sshversion = line.match(SSHVERSION_REGEX)
    disconnect = line.match(DISCONNECTION_REGEX)
    auth_attempt = line.match(AUTH_ATTEMPT)
    login_attempt = line.match(LOGIN_ATTEMPT)
    login_success = line.match(LOGIN_SUCCESS)
    cmd_run = line.match(CMD_RUN)

    if new_connection
      puts "New Connection from #{new_connection[1]} - Session number #{new_connection[2]}".red
    elsif sshversion
      puts sshversion[1].yellow
    elsif disconnect
      puts "Lost Connection from #{disconnect[2]} - Session number #{disconnect[1]}".red
    elsif auth_attempt
      puts "AUTH ATTEMPT FROM #{auth_attempt[2]} - #{auth_attempt[3]} - Session number #{auth_attempt[1]}".blue
    elsif login_attempt
      puts "LOGIN ATTEMPT FROM #{login_attempt[2]} - User/Password: #{login_attempt[3]}/#{login_attempt[4]} - Status: #{login_attempt[5]} - Session Number #{login_attempt[1]}".blue
    elsif login_success
      puts "LOGIN SUCCESS - #{login_success[3]}@#{login_success[2]} vis #{login_success[4]} - Session Number #{login_success[1]}".green
    elsif cmd_run
      puts "COMMAND FROM #{cmd_run[2]} | #{cmd_run[3]} | Session Number #{cmd_run[1]}".green
    end
  end
end
