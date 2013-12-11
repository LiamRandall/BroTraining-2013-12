## Exiftool is written in Perl.  This script is probably a bad idea to 
## actually use because it will result in potentially spawning a large
## number of Perl processes.  It can also cause a lot of file extraction
## which can be bad for performance.  It is a reasonably good example of running
## a command line tool against an extracted file.

module Exiftool;

export {
	## The logging identifier creation.
	redef enum Log::ID += { LOG };
	
	## A pattern of file types to scan with exiftool.
	const scan_files = /application\/x-dosexec/ |
	                   /image\/jpeg/ &redef;
	
	## The event that is called once the exiftool result is achieved.
	global output: event(f: fa_file, r: table[string] of string);
	
	## Full path to call exiftool.  If exiftool is in your default path this 
	## can be left alone.
	const cmd = "exiftool" &redef;
	
	type Info: record {
		## A timestamp representing when exiftool finished.
		ts:   time             &log;
		## The file unique ID in question.
		fuid: string           &log;
		## An ordered vector of all of the keys from exiftool
		keys: vector of string &log;
		## An ordered vector of all of the values from exiftool
		vals: vector of string &log;
	};
}

redef record fa_file += {
	# If you set this value to T in a file_new handler it will begin the 
	# process for exiftool.  Use this if you need more flexibility than the 
	# scan_files varibles provides.
	exiftool: bool &default=T;
};

# Create the log stream so that logging will work.
event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info]);
	}

# Define this at a higher priority so that the scan_files configuration option
# works.
event file_new(f: fa_file) &priority=5
	{
	if ( f?$mime_type && scan_files in f$mime_type )
		f$exiftool = T;
	}

# Define this at a lower priority so that the extraction can be enabled for 
# anything with the exiftool flag set.
event file_new(f: fa_file) &priority=-5
	{
	if ( f$exiftool )
		Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
	}

event file_state_remove(f: fa_file)
	{
	# If exiftool was run on the file then do this stuff.
	if ( f$exiftool )
		{
		# Actually run the command.
		when ( local result = Exec::run([$cmd=fmt("%s -s -s %s/%s", cmd, FileExtract::prefix, f$info$extracted)]) )
			{
			# If the command succeeded..
			if ( result$exit_code == 0 )
				{
				# Collect the data from stdout and write the log.
				local out = result$stdout;
				local keys: vector of string;
				local vals: vector of string;
				for ( i in out )
					{
					local parts = split1(out[i], /: /);
					keys[|keys|] = parts[1];
					vals[|vals|] = parts[2];
					}
				Log::write(LOG, Info($ts=network_time(), 
				                     $fuid=f$id, 
				                     $keys=keys, $vals=vals));
				}
			}
		}
	}
	
	
	
	
