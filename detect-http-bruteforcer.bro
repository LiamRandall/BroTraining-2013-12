##! HTTP brute-forced server detector
##!	Version: Bro 2.2
##! Watch for 

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
		## Indicates that a host may be performing HTTP brute force attacks
		HTTP_BruteForce_Attacker ,
		## Indicates that a host was seen to be returning a large number of
		## HTTP 404 errors.  May indicate brute forcing
		HTTP_BruteForce_Victim,
	};

	## How many rejected usernames or passwords are required before being
	## considered to be bruteforcing.
	const http_bruteforcer_threshold: double = 25 &redef;

	## The time period in which the threshold needs to be crossed before
	## being reset.
	const http_bruteforcer_measurement_interval = 15mins &redef;
}


event bro_init()
	{
	local r1: SumStats::Reducer = [$stream="http-bruteforcer.client_404", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(http_bruteforcer_threshold+2)];
	SumStats::create([$name="http-bruteforcer-client_404",
	                  $epoch=http_bruteforcer_measurement_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["http-bruteforcer.client_404"]$num+0.0;
	                  	},
	                  $threshold=http_bruteforcer_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["http-bruteforcer.client_404"];
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local plural = r$unique>1 ? "s" : "";
	                  	local message = fmt("%s generated at least %d distinct HTTP 404 Errors on %d HTTP basic auth server%s in %s", key$host, r$num, r$unique, plural, dur);
	                  	NOTICE([$note=HTTP::HTTP_BruteForce_Attacker,
	                  	        $src=key$host,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if (c$http?$status_code && c$http$status_code == 404) # && c$http?$password
		{
			SumStats::observe("http-bruteforcer.client_404", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
		}

	}

