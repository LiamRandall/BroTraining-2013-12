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
		## Indicates that a host was seen to be returning a large number of
		## HTTP 404 errors.  May indicate brute forcing
		HTTP_Server_High_404,
	};

	## How many rejected usernames or passwords are required before being
	## considered to be bruteforcing.
	const http_server_high_404_threshold: double = 25 &redef;

	## The time period in which the threshold needs to be crossed before
	## being reset.
	const http_server_404_measurement_interval = 15mins &redef;

	## URI's to ignore
	const http_uri_whitelist = set("/favicon.ico");

	## responder whitelist; do not track these sites
	## TODO: implement domain whitelist w/ regex
	const http_resp_whitelist = set("local.cnn.com","ads.cnn.com");

	## originator whitelists
	const http_orig_whitelist = set(192.168.0.1);
}


event bro_init()
	{
	local r1: SumStats::Reducer = [$stream="http-server.high_404", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(http_server_high_404_threshold+2)];
	SumStats::create([$name="http-server-high-404",
	                  $epoch=http_server_404_measurement_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["http-server.high_404"]$num+0.0;
	                  	},
	                  $threshold=http_server_high_404_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["http-server.high_404"];
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local plural = r$unique>1 ? "s" : "";
	                  	local message = fmt("Local Server %s generated at least %d HTTP 404 Errors from %d client%s in %s", key$host, r$num, r$unique, plural, dur);
	                  	NOTICE([$note=HTTP::HTTP_Server_High_404,
	                  	        $src=key$host,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
    # Whitelist certain URI's; especially the favicon.ico which is commonly not setup
    if ((c$http?$uri) && (c$http$uri in http_uri_whitelist))
	   	return;

    if ((c$http?$host) && (c$http$host in http_resp_whitelist))
	   	return;

	if ((c$id?$orig_h) && (c$id$orig_h in http_orig_whitelist))
		return;


	if (c$http?$status_code && c$http$status_code == 404) # && c$http?$password
		{
			SumStats::observe("http-server.high_404", [$host=c$id$resp_h], [$str=cat(c$id$orig_h)]);
		}

	}

