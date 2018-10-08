#!/bin/bash
set -u

#version number
VERSION=1.1.4

#Maximum 24-bit integer
MAX=16777215

#Maximum prime that statisfies p mod 4 = 3
MAXPRIME=16777127

### Configurable parameters
# Number of parallel traceroutes that will run
PARALLEL=${PARALLEL-128}

# Scamper packets per second rate 1<=pps<=1000
PPS=${PPS-1000}

# Directory to temporarily store traceroute results
RESULTS=${RESULTS-"Traceroute-results"}

# File logging debug messages
DEBUGLOG=${DEBUGLOG-"Debug.log"}

# Traceroute command
TRACEROUTE=${TRACEROUTE-"traceroute -n -m 30 -w 5"}

# Scamper command
SCAMPER=${SCAMPER-"scamper -c trace"}

### These can be useful to change during testing
# How big a directory is OK
DIRSIZE=${DIRSIZE-65536}

# Destination
DESTHOST=${DESTHOST-"tor-traceroutes@ttat-control.iti.illinois.edu"}

# File containing the start and end IP of each routable prefix obtained from Route-Views project (http://www.routeviews.org/)
PREFIX_FILE=${PREFIX_FILE-prefix.txt}

# File containing the list of Tor relay IPs that appeared during 9/19/13-9/25-13
RELAY_FILE=${RELAY_FILE-"relay-ips.txt"}

# File containing allowed (not reserved) IP ranges
ALLOWED_FILE=${ALLOWED_FILE-"allowed-ips.txt"}


# Make a directory to store the results
mkdir -p "$RESULTS" && cd "$RESULTS" || exit

compsuffix=.Z
if type bzip2 &>/dev/null; then
    compress () { bzip2 -f ; }
    compsuffix=.bz2
elif type gzip &>/dev/null; then
    compress () { gzip -f ; }
    compsuffix=.gz
elif ! type compress &>/dev/null; then
    # BSD compress doesn't exist, send things
    # uncompressed
    compress () { cat ; }
    compsuffix=
fi

if [[ ! -z "${DONTERASE+yes}" ]]; then
    # Never erase anything
    rm () { : ; }
fi
if [[ ! -z "${DONTUPLOAD+yes}" ]]; then
    # Don't upload anything
    ssh () { cat >/dev/null ; }
fi

# Set METHOD=traceroute to always do traceroute instead of
# trying scamper
if [[ ${METHOD-scamper} =~ traceroute ]] || ! eval $SCAMPER -i 200.3.220.7 &>/dev/null; then
# Use traceroute
    function method_startset {
    	count=0  #current number of traceroutes
        curdirnum=0 #current wokring set of DIRSIZE traceroutes
        curdir=$prefix-$curdirnum
        mkdir $curdir
    }
    function compress_and_upload  {
        # Wait for all traceroutes in this set to be finished
        wait
        tar cf - $curdir/ | compress | ssh -F ../ssh-config $DESTHOST $curdir.traceroute-$PARALLEL-$VERSION.tar$compsuffix
        rm -r $curdir/
    }
    function process_ip {
        while [ $(jobs | wc -l) -ge $PARALLEL ]; do
            sleep 1 # run only fixed number of traceroutes in parallel
        done
	# Debug mode only for traceroute method, print # of parallel traceroutes & traceroute runtime
	if [[ ${DEBUG-no} =~ yes ]] ; then 
		printf "%s" $(date +%s)" DEBUG: Running traceoutes = " >> $DEBUGLOG
	        ps -e | sed '/traceroutes.sh/d' | grep 'traceroute' |wc -l >> $DEBUGLOG 
		(time -p eval $TRACEROUTE $1 </dev/null 2>&1 | filter) >> $curdir/$1.trt 2>&1 &
	else
        	eval $TRACEROUTE $1 </dev/null 2>&1 | filter >> $curdir/$1.trt &
        fi

        ((++count))
        # Check if the directory has reached a certain size
        if [ $((count % DIRSIZE)) -eq 0 ]; then
            compress_and_upload
            ((++curdirnum))
            curdir=$prefix-$curdirnum
            mkdir $curdir
        fi
    }
    function endset { compress_and_upload; }
else
    function method_startset {
       count=0  #current number of traceroutes
       curdirnum=0 #current wokring set of DIRSIZE traceroutes
       rm -f *.ips # Clear the IP file if it happens to exist
    }
    function run_scamper {
    	eval $SCAMPER -p $PPS $prefix-$curdirnum.ips | filter >> $prefix-$curdirnum.scamper
    	cat $prefix-$curdirnum.scamper | compress  | ssh -F ../ssh-config $DESTHOST $prefix-$curdirnum.scamper-$PPS-$VERSION$compsuffix
        rm -f $prefix-$curdirnum.ips  # remove the IP file
        rm -f $prefix-$curdirnum.scamper #remove results
    }
    function process_ip {
    	((++count))
        if [[ $((count%DIRSIZE)) -eq 0 ]]; then # do scamper for every /8 prefix
        	 run_scamper
            	((++curdirnum))
        fi
        echo $1 >> $prefix-$curdirnum.ips
    }
    function endset {
    	 run_scamper #if any IPs remain
    }
fi

function startset {
    prefix=$1-$(date +%s)-$(hostname)
    if [[ $2 -eq 0 ]]; then
        function filter { sed -e 's/ *[0-9.]* ms//g' ; }
    else
        function filter { cat ; }
    fi
    method_startset
}

#Randomize IP 
function randomize {
    if [[ $1 -ge $MAXPRIME ]]; then
	 ip=$1 
    else
	 residue=$(( ($1*$1)%MAXPRIME ))
	 if [[ $1 -le $((MAXPRIME/2)) ]]; then
		ip=$residue
	 else
		ip=$((MAXPRIME - residue))
    	 fi
    fi  
}

## Routeviews prefixes
startset routeviews 0

while IFS="|" read start_ip end_ip; do
	#Compute the range (in decimal format) of a prefix
	range=$((end_ip - start_ip + 1))

	if [ $range -eq 0 ]; then
		ip=$start_ip #only one feasible address special case for /31 prefixes
	elif [ $range -lt 0 ]; then
		ip=$((start_ip-1)) #use the exact IP for /32 prefixes
	else
		ip=$((start_ip+$RANDOM%range)) #Randomly choose an IP from a prefix
	fi
	process_ip $ip
done < ../$PREFIX_FILE

endset

## Tor relays, record latency information
startset relays 1

while read ip; do
	process_ip $ip
done < ../$RELAY_FILE

endset

## All /24 prefixes
startset slash24 0

ip=0 #variable to hold randomized ip
TOGGLE=$(( (RANDOM & 511)<<15 | RANDOM )) #random bit toggle
i=0 #counter for going through all /24 ip

while [ $i -le $MAX ]; do
	randomize $i
	ip=$((ip^TOGGLE))
        randomize $ip 
	ip=$(( (ip<<8) + RANDOM%254 + 1 )) # Host between .1 and .254
	allowed=0 #variable to check if ip in restricted zone
	while read start end; do
      		if [[ $ip -ge $start && $ip -lt $end ]]; then
			allowed=1 # valid ip
			break
		fi
	done < ../$ALLOWED_FILE
	if [[ $allowed -eq 1 ]]; then
		process_ip $ip
	fi
	i=$((i+1))
done

endset

cd ..
rm -r "$RESULTS"