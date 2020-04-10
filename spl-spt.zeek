@load base/protocols/ssl

module SPL;

export {
	const spl_length = 20 &redef;
	const spt_length = 20 &redef;
}

redef record SSL::Info += {
	orig_spl:	vector of count &log &optional;
	resp_spl:	vector of count &log &optional;

	orig_spt:	vector of double &log &optional;
	resp_spt:	vector of double &log &optional;

# Used to calculate packet times. Shouldn't be logged
	last_time: time &optional;
};

redef SSL::disable_analyzer_after_detection=F;

# redef LogAscii::use_json = T;

event ssl_encrypted_data(c: connection, is_orig: bool, record_version: count, content_type: count, len: count) {
	if ( ! c ?$ ssl )
		return;

	if ( is_orig == T ) {
		if ( c$ssl ?$ orig_spl == F ) {
			c$ssl$orig_spl = vector(len);
		} else {
			if ( |c$ssl$orig_spl| < spl_length ) {
				c$ssl$orig_spl += len;
			}
		}

		if ( ! c$ssl ?$ orig_spt ) {
			c$ssl$orig_spt = vector(0.00);
			c$ssl$last_time = network_time();
		} else {
			if ( |c$ssl$orig_spt| < spt_length ) {
				local o_c_time = network_time();
				c$ssl$orig_spt += interval_to_double(o_c_time - c$ssl$last_time);
				c$ssl$last_time = o_c_time;
			}
		}
		return;
	}
	if ( is_orig == F ) {
		if ( ! c$ssl ?$ resp_spl ) {
			c$ssl$resp_spl = vector(len);
		} else {
			if ( |c$ssl$resp_spl| < spl_length ) {
				c$ssl$resp_spl += len;
			}
		}

		if ( ! c$ssl ?$ resp_spt ) {
			c$ssl$resp_spt = vector(0.00);
			c$ssl$last_time = network_time();
		} else {
			if ( |c$ssl$resp_spt| < spt_length ) {
				local r_c_time = network_time();
				c$ssl$resp_spt += interval_to_double(r_c_time - c$ssl$last_time);
				c$ssl$last_time = r_c_time;
			}
		}
	}

	#print to_json(c$ssl); # debug print
}