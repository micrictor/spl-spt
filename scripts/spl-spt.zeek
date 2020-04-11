@load base/protocols/ssl
@load base/protocols/conn

module SPL;

export {
	const spl_length = 20 &redef;
	const spt_length = 20 &redef;

	redef enum Log::ID += { LOG };

	type Info: record {
		# Not actually optional, but we load it in last
		uid: string &log &optional;

		orig_spl:	vector of count &log &optional;
		resp_spl:	vector of count &log &optional;

		orig_spt:	vector of double &log &optional;
		resp_spt:	vector of double &log &optional;

		# Track the time of the last packet
		last_time: 	time &optional;
	};
}

# We need to store the vectors in the SSL record until the connection ends
redef record connection += {
	spl: SPL::Info &optional;
};

# Enable ssl_encrypted_data event
redef SSL::disable_analyzer_after_detection=F;

event zeek_init() &priority=5
{
    # Create the stream. This adds a default filter automatically.
    Log::create_stream(SPL::LOG, [$columns=SPL::Info, $path="spl"]);
}

event ssl_encrypted_data(c: connection, is_orig: bool, record_version: count, content_type: count, len: count) {
	if ( ! c ?$ spl )
		c$spl = SPL::Info();

	if ( is_orig == T ) {
		if ( c$spl ?$ orig_spl == F ) {
			c$spl$orig_spl = vector(len);
		} else {
			if ( |c$spl$orig_spl| < spl_length ) {
				c$spl$orig_spl += len;
			}
		}
		if ( ! c$spl ?$ orig_spt ) {
			c$spl$orig_spt = vector(0.00);
			c$spl$last_time = network_time();
		} else {
			if ( |c$spl$orig_spt| < spt_length ) {
				local o_c_time = network_time();
				c$spl$orig_spt += interval_to_double(o_c_time - c$spl$last_time);
				c$spl$last_time = o_c_time;
			}
		}
		return;
	}
	if ( is_orig == F ) {
		if ( ! c$spl ?$ resp_spl ) {
			c$spl$resp_spl = vector(len);
		} else {
			if ( |c$spl$resp_spl| < spl_length ) {
				c$spl$resp_spl += len;
			}
		}

		if ( ! c$spl ?$ resp_spt ) {
			c$spl$resp_spt = vector(0.00);
			c$spl$last_time = network_time();
		} else {
			if ( |c$spl$resp_spt| < spt_length ) {
				local r_c_time = network_time();
				c$spl$resp_spt += interval_to_double(r_c_time - c$spl$last_time);
				c$spl$last_time = r_c_time;
			}
		}
	}
}

event connection_state_remove(c: connection) {
	if ( ! c ?$ spl )
		return;

	c$spl$uid = c$uid;

	Log::write(SPL::LOG, c$spl);
}