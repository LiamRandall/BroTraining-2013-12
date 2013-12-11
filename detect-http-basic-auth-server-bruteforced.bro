##! HTTP basic-auth brute-forced server detector

##! 	detect servers under potential brute force attack / misconfiguration
##!		tracking for servers (by IP, not HOST) throwing a high number of 401's

##!	Improvements & derivatives
##!		- Presently watches for attempts with a user
##!		  Break that into two seperate heuristics- track attempts by user, distinct passwords
##!		  could identify misconfigured services sending same user/password over & over again 
##!		- Implement check for "HTTP::default_capture_password=T" and if so also check for "&& c$http?$password"
##!		- Track heuristics by client / host, client/ ip address, client / subnet
##!		- Dynamicaly detect if "HTTP::default_capture_password=T"
##!		- Right now tracking for BOTH local and remote connections; will catch inbound & outbound attackers
##!		  can enable remote only with is_local_addr


@load base/protocols/http
@load base/frameworks/sumstats

@load base/utils/time

module HTTP;

export {
	redef enum Notice::Type += {
		## Indicates a host bruteforcing HTTP Basic Auth logins by watching for too many
		## rejected usernames or failed passwords.
		HTTP_Basic_Auth_Server_Bruteforced
	};

	## How many rejected usernames or passwords are required before being
	## considered to be bruteforcing.
	const basic_auth_bruteforced_server_threshold: double = 20 &redef;

	## The time period in which the threshold needs to be crossed before
	## being reset.
	const basic_auth_bruteforced_server_measurement_interval = 15mins &redef;
}


event bro_init()
	{
	local r1: SumStats::Reducer = [$stream="http-basic-auth.server_401", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(basic_auth_bruteforced_server_threshold+2)];
	SumStats::create([$name="http-basic-auth-detect-server-bruteforced",
	                  $epoch=basic_auth_bruteforced_server_measurement_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["http-basic-auth.server_401"]$num+0.0;
	                  	},
	                  $threshold=basic_auth_bruteforced_server_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["http-basic-auth.server_401"];
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local plural = r$unique>1 ? "s" : "";
	                  	local message = fmt("%s had %d failed basic http auth logins from %d clients%s in %s", key$host, r$num, r$unique, plural, dur);
	                  	NOTICE([$note=HTTP::HTTP_Basic_Auth_Server_Bruteforced,
	                  	        $src=key$host,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if (c$http?$status_code && c$http$status_code == 401 && c$http?$username) # && c$http?$password
		{
#			SumStats::observe("http-basic-auth.server_401", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
			SumStats::observe("http-basic-auth.server_401", [$host=c$id$resp_h], [$str=cat(c$id$orig_h)]);
		}

	}

