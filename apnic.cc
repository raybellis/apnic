/*
 * $Id: $
 *
 * Copyright (c) 2014 - 2015, Nominet UK.
 * Copyright (c) 2015, Internet Systems Consortium, Inc. (ISC)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *	 * Neither the name of Nominet UK or ISC nor the names of its contributors
 *	   may be used to endorse or promote products derived from this software
 *	   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Nominet UK and ISC ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Nominet UK or ISC BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string>
#include <stdexcept>
#include <iostream>
#include <map>

#include <cstdlib>
#include <cstdio>

#include <evldns.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <limits.h>

#if MALLOC_DEBUG
#include <malloc.h>
#endif

#include <openssl/crypto.h>

using std::string;

class APZone {

public:
	ldns_dnssec_zone	*zone;
	ldns_rr_list		*ds;
	ldns_rr_list		*ds_rrsig;
	time_t				 created;

public:
	APZone(ldns_dnssec_zone *zone, ldns_rr_list *ds, ldns_rr_list *ds_rrsig);
	~APZone();
};

APZone::APZone(ldns_dnssec_zone *zone, ldns_rr_list *ds, ldns_rr_list *ds_rrsig)
: zone(zone), ds(ds), ds_rrsig(ds_rrsig)
{
	this->created = time((time_t *)0);
}

APZone::~APZone()
{
	ldns_dnssec_zone_deep_free(zone);
	if (ds_rrsig) {
		ldns_rr_list_deep_free(ds_rrsig);
	}
	if (ds) {
		ldns_rr_list_deep_free(ds);
	}
}

struct cmp_ldns_rdf {
	bool operator()(const ldns_rdf *a, const ldns_rdf *b) const {
		return ldns_dname_compare(a, b) < 0;
	}
};

class APNIC {

	typedef std::map<ldns_rdf*, APZone*,cmp_ldns_rdf>	 ChildMap;

private:
	string							 key_file;
	string							 parent_file;
	string							 child_file;
	string							 log_path;

private:
	ldns_rdf						*origin;
	int								 origin_count;
	ldns_dnssec_zone				*parent_zone;
	ldns_key_list					*parent_keys;
	ChildMap						 children;
	pthread_mutex_t					 mutex;
	time_t							 loglast;
	int								 logfd;

private:
	ldns_dnssec_zone *load_zone(ldns_rdf *origin, string zonefile);
	void add_keys(ldns_dnssec_zone *zone, ldns_key_list *keys);
	void sign_zone(ldns_dnssec_zone *zone, ldns_key_list *keys);
	ldns_key_list *create_signing_key(ldns_rdf *origin);
	void create_parent_zone();
	APZone *create_child_zone(ldns_rdf *origin);

	void zone_lookup(ldns_pkt *resp, ldns_dnssec_zone *zone, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit);
	void synthesize_ds_record(ldns_pkt *resp, ldns_rdf *qname, APZone *apz, bool do_bit);
	void parent_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit);
	void child_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit);
	int openlog(time_t t);

public:
	APNIC(string domain, string keyfile, string parentfile, string childfile, string logpath);
	~APNIC();

public:
	void kill_orphans();
	void callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass);
};

// --------------------------------------------------------------------

void rr_list_cat_dnssec_rrs_clone(ldns_rr_list *rr_list, ldns_dnssec_rrs *rrs)
{
	while (rrs) {
		ldns_rr_list_push_rr(rr_list, ldns_rr_clone(rrs->rr));
		rrs = rrs->next;
	}
}

void rr_list_cat_rr_list_clone(ldns_rr_list *dst, ldns_rr_list *src)
{
	for (int i = 0, n = ldns_rr_list_rr_count(src); i < n; ++i) {
		ldns_rr_list_push_rr(dst, ldns_rr_clone(ldns_rr_list_rr(src, i)));
	}
}

// --------------------------------------------------------------------

APNIC::APNIC(string domain, string key_file, string parent_file, string child_file, string log_path)
: key_file(key_file), parent_file(parent_file), child_file(child_file), log_path(log_path)
{
	origin = ldns_dname_new_frm_str(domain.c_str());
	origin_count = ldns_dname_label_count(origin);

	create_parent_zone();
	pthread_mutex_init(&mutex, NULL);

	logfd = -1;
	openlog(time(NULL));
}

APNIC::~APNIC()
{
	pthread_mutex_destroy(&mutex);
	ldns_dnssec_zone_deep_free(parent_zone);
	ldns_rdf_deep_free(origin);
}

ldns_key_list *APNIC::create_signing_key(ldns_rdf *origin)
{
	FILE *fp = fopen(key_file.c_str(), "r");
	if (!fp) {
		throw std::runtime_error("open key file: " + string(strerror(errno)));
	}

	ldns_key *key;
	ldns_status status = ldns_key_new_frm_fp(&key, fp);
	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("error loading key file: " + string(ldns_get_errorstr_by_id(status)));
	}
	fclose(fp);

	ldns_key_list *list = ldns_key_list_new();
	ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));
	ldns_key_set_inception(key, (time(NULL)-3600));
	ldns_key_list_push_key(list, key);

	return list;
}

ldns_dnssec_zone *APNIC::load_zone(ldns_rdf *origin, string zonefile)
{
	ldns_dnssec_zone *zone;

	/* load zone file */
	FILE *fp = fopen(zonefile.c_str(), "r");
	if (!fp) {
		throw std::runtime_error("open zone file: " + zonefile + " - " + string(strerror(errno)));
	}
	ldns_status status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin, 60, LDNS_RR_CLASS_IN);
	fclose(fp);

	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("error loading zone file: " + string(ldns_get_errorstr_by_id(status)));
	}

	return zone;
}

void APNIC::add_keys(ldns_dnssec_zone *zone, ldns_key_list *keys)
{
	for (int i = 0, n = ldns_key_list_key_count(keys); i < n; ++i) {
		ldns_rr *rr = ldns_key2rr(ldns_key_list_key(keys, i));
		ldns_dnssec_zone_add_rr(zone, rr);
	}
}

void APNIC::sign_zone(ldns_dnssec_zone *zone, ldns_key_list *keys)
{
	ldns_rr_list *new_rrs = ldns_rr_list_new();
	ldns_status status = ldns_dnssec_zone_sign(zone, new_rrs, keys, ldns_dnssec_default_replace_signatures, 0);
	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("error signing zone file: " + string(ldns_get_errorstr_by_id(status)));
	}

	/* we don't need the extra list of RRs */
	ldns_rr_list_free(new_rrs);
}

void APNIC::create_parent_zone()
{
	parent_zone = load_zone(origin, parent_file);
	parent_keys = create_signing_key(this->origin);
	add_keys(parent_zone, parent_keys);
	sign_zone(parent_zone, parent_keys);
}

APZone *APNIC::create_child_zone(ldns_rdf *origin)
{
	/* to hold copy of child_file */
	string	cfile(child_file);

	/* get string from query name, and check for which zone to serve */
	ldns_buffer *qname_buf = ldns_buffer_new(256);
	ldns_rdf2buffer_str_dname(qname_buf, origin);

	/* to check query attributes at front of name */
	char *qbuf = (char *)ldns_buffer_export(qname_buf);
	int qlen = strlen(qbuf);

	/* default state */
	bool is_signed = true;
	bool is_broken = true;

	if (qlen >= 3) {
		if (qbuf[2] == 'u') {
			is_signed = false;
			is_broken = false;
		} else if (qbuf[2] == 'i') {
			// no change
		} else if (qbuf[2] == 's') {
			is_broken = false;
		}

		/* create the specific child zone */
		string::reverse_iterator r = cfile.rbegin();
		r[0] = qbuf[1];
		r[1] = qbuf[0];
	}

	/* qname_buf is no longer needed */
	ldns_buffer_free(qname_buf);
	free(qbuf);

	/* to check file accessibility */
	int status = access(cfile.c_str(), R_OK);

	/* serve base zone unsigned */
	ldns_dnssec_zone *child_zone;

	if (status != 0 || qlen < 3) {
		// fprintf(stdout, "can't serve %s\n", cfile.c_str());
		child_zone = load_zone(origin, child_file);
	} else {
		// fprintf(stdout, "serve %s\n", cfile.c_str());
		child_zone = load_zone(origin, cfile);
	}

	if (!is_signed) {
		return new APZone(child_zone, NULL, NULL);
	}

	ldns_key_list *child_keys = create_signing_key(origin);
	/* add child keys to the zone */
	add_keys(child_zone, child_keys);
	/* sign the child zone */
	sign_zone(child_zone, child_keys);


	/* create a list of DS record for this child, relying on key's
	   public owner being set by previous function */
	ldns_rr_list *ds_list = ldns_rr_list_new();
	for (int i = 0, n = ldns_key_list_key_count(child_keys); i < n; ++i) {
		ldns_rr *key_rr = ldns_key2rr(ldns_key_list_key(child_keys, i));
		ldns_rr *ds = ldns_key_rr2ds(key_rr, LDNS_SHA1);

		/* if required, change the DS record RDATA so it doesn't actually
		   match the given key, breaking the signature chain */
		if (is_broken) {
			uint16_t *tag = (uint16_t *)ldns_rdf_data(ldns_rr_rdf(ds, 0));
			*tag ^= -1;			/* invert key tag bits */

			uint8_t *hex = ldns_rdf_data(ldns_rr_rdf(ds, 3));
			*hex ^= -1;			/* invert first byte of DS hex */
		}

		ldns_rr_list_push_rr(ds_list, ds);
		ldns_rr_free(key_rr);
	}

	/* child keys no longer required */
	ldns_key_list_free(child_keys);

	/* create RRSIGs over the DS - NB: requires the parent origin */
	ldns_rr_list *ds_rrsig = ldns_sign_public(ds_list, parent_keys);

	return new APZone(child_zone, ds_list, ds_rrsig);
}

void APNIC::zone_lookup(ldns_pkt *resp, ldns_dnssec_zone *zone, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class /* qclass */, bool do_bit)
{
	/* check if the zone was signed */
	bool is_signed = zone->soa->nsec;

	/* cribbed from ldns_dnssec_zone_find_rrset */
	ldns_rbnode_t *node = 0;
	int match = ldns_rbtree_find_less_equal(zone->names, qname, &node);

	/* this shouldn't happen */
	if (!node) {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_SERVFAIL);
		return;
	}

	/* extract that nearest node */
	ldns_dnssec_name *name = (ldns_dnssec_name*)node->data;

	/* do we need to prove non-existence */
	bool need_proof = false;

	/* RRs will drop in here */
	ldns_rr_list *answer = ldns_pkt_answer(resp);
	ldns_rr_list *authority = ldns_pkt_authority(resp);

	/* check for existing domain */
	if (match) {
		/* special handling for exact NSEC queries */
		if (is_signed && qtype == LDNS_RR_TYPE_NSEC) {
			ldns_rr_list_push_rr(answer, ldns_rr_clone(name->nsec));
			if (do_bit) {
				rr_list_cat_dnssec_rrs_clone(answer, name->nsec_signatures);
			}
		} else {
			/* check for correct qtype */
			ldns_dnssec_rrsets *rrsets = ldns_dnssec_name_find_rrset(name, qtype);

			/* add records and RRSIGs if found */
			if (rrsets) {
				rr_list_cat_dnssec_rrs_clone(answer, rrsets->rrs);
				if (is_signed && do_bit) {
					rr_list_cat_dnssec_rrs_clone(answer, rrsets->signatures);
				}
			} else {
				need_proof = 1;
			}
		}
	} else {
		node = ldns_rbtree_next(node);
		name = (ldns_dnssec_name*)node->data;
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
		need_proof = 1;
	}

	/* add SOA and NSECS to the response if needed */
	if (need_proof) {

		/* find the SOA for this zone */
		ldns_dnssec_name *soa = zone->soa;
		ldns_dnssec_rrsets *rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);

		/* add the SOA */
		if (rrsets) {
			rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
			/* and its signature */
			if (is_signed && do_bit) {
				rr_list_cat_dnssec_rrs_clone(authority, rrsets->signatures);
			}
		}

		if (is_signed && do_bit) {
			/* add NSEC and RRSIGs for the SOA */
			ldns_rr_list_push_rr(authority, ldns_rr_clone(soa->nsec));
			rr_list_cat_dnssec_rrs_clone(authority, soa->nsec_signatures);

			/* include original owner name NSEC if it's not the SOA */
			if (name && (ldns_dnssec_name_cmp(soa, name) != 0)) {
				ldns_rr_list_push_rr(authority, ldns_rr_clone(name->nsec));
				rr_list_cat_dnssec_rrs_clone(authority, name->nsec_signatures);
			}
		}
	}
}

void APNIC::parent_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit)
{
	zone_lookup(resp, parent_zone, qname, qtype, qclass, do_bit);
}

void APNIC::synthesize_ds_record(ldns_pkt *resp, ldns_rdf* qname, APZone *apz, bool do_bit)
{
	ldns_rr_list *answer = ldns_pkt_answer(resp);

	/* add the DS rr_list to the answer */
	rr_list_cat_rr_list_clone(answer, apz->ds);

	/* include RRSIG over the DS, if required */
	if (do_bit) {
		rr_list_cat_rr_list_clone(answer, apz->ds_rrsig);

		/* if the DS doesn't even exist, create an NSEC record for it */
		if (!apz->ds) {

			ldns_rr_list *authority = ldns_pkt_authority(resp);

			/* include the SOA */
			ldns_dnssec_name *soa = parent_zone->soa;
			ldns_dnssec_rrsets *rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);

			if (rrsets) {
				rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
				if (do_bit) {
					/* and its signature */
					rr_list_cat_dnssec_rrs_clone(authority, rrsets->signatures);

					/* SOA's NSEC and RRSIGS */
					/* ldns_rr_list_push_rr(authority, ldns_rr_clone(soa->nsec)); */
					/* rr_list_cat_dnssec_rrs_clone(authority, soa->nsec_signatures); */
				}
			}

			if (do_bit) {
				/* owner name NSEC and RRSIGS */
				ldns_rdf *next = ldns_dname_new_frm_data(3, (void *)"\001\000\000");
				ldns_dname_cat(next, qname);
				ldns_rr *nsec = ldns_create_nsec(qname, next, NULL);
				ldns_rdf_deep_free(next);

				/* fake NS type field */
				ldns_nsec_bitmap_set_type(ldns_nsec_get_bitmap(nsec), LDNS_RR_TYPE_NS);
				ldns_rr_list *nsecs = ldns_rr_list_new();
				ldns_rr_list_push_rr(nsecs, nsec);

				/* sign it */
				ldns_rr_list *rrsigs = ldns_sign_public(nsecs, parent_keys);

				/* add to the response */
				ldns_rr_list_push_rr_list(authority, nsecs);
				ldns_rr_list_push_rr_list(authority, rrsigs);

				/* free the local lists  - the authority section now owns the RRs */
				ldns_rr_list_free(rrsigs);
				ldns_rr_list_free(nsecs);
			}
		}
	}
}

void APNIC::kill_orphans()
{
	/* what time is it? */
	time_t now = time((time_t *)0);
	time_t then = now - 20;

	pthread_mutex_lock(&mutex);
	ChildMap::iterator it = children.begin();
	while (it != children.end()) {
		APZone *apz = it->second;
		if (apz->created < then) {
			ldns_rdf_deep_free(it->first);
			delete apz;
			children.erase(it++);
		} else {
			++it;
		}
	}
	pthread_mutex_unlock(&mutex);
}

void APNIC::child_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit)
{
	/* extract the subdomain name, based on the last label before the parent */
	int qname_count = ldns_dname_label_count(qname);
	int label_count = qname_count - origin_count;
	ldns_rdf *child = ldns_dname_clone_from(qname, label_count - 1);

	/* there isn't really a wildcard here */
	if (ldns_dname_is_wildcard(child)) {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
		ldns_rdf_deep_free(child);
		return;
	}

	/* look up the zone from cache, or create a new one */
	pthread_mutex_lock(&mutex);
	ChildMap::iterator it = children.find(child);
	APZone *apz = (it == children.end()) ? NULL : it->second;
	if (!apz) {
		/* unlock temporarily while we do crypto */
		pthread_mutex_unlock(&mutex);

		/* do that crypto */
		apz = create_child_zone(child);

		/* lock again while we update the map */
		pthread_mutex_lock(&mutex);

		/* make sure the map wasn't updated while we were signing */
		if ((it = children.find(child)) == children.end()) {
			ldns_rdf *child_key = ldns_rdf_clone(child);
			children[child_key] = apz;
		} else {
			/* if it was, discard the newly created zone and use the old one again */
			delete apz;
			apz = it->second;
		}
	}

	/* pretend to be the parent zone if asking for a DS record */
	if (label_count == 1 && qtype == LDNS_RR_TYPE_DS) {
		synthesize_ds_record(resp, child, apz, do_bit);
	} else {
		zone_lookup(resp, apz->zone, qname, qtype, qclass, do_bit);
	}

	ldns_rdf_deep_free(child);
	pthread_mutex_unlock(&mutex);
}

int APNIC::openlog(time_t t)
{
	static int interval = 86400;

	if (logfd < 0 || (t % interval < loglast % interval)) {
		close(logfd);
		char path[_POSIX_PATH_MAX];

		time_t tzero = t - t % interval;
		strftime(path, _POSIX_PATH_MAX, log_path.c_str(), gmtime(&tzero));
		logfd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
	}
	loglast = t;

	return logfd > 0 ? logfd : 0;
}

void APNIC::callback(evldns_server_request *srq,
				 ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	/* log request time for later */
	timeval tv;
	gettimeofday(&tv, NULL);

	/* check if the domain is an exact match or subdomain */
	bool is_top_domain = (ldns_dname_compare(qname, origin) == 0);
	bool is_sub_domain = !is_top_domain && ldns_dname_is_subdomain(qname, origin);

	/* query isn't for this domain */
	if (!is_top_domain && !is_sub_domain) {
		return;
	}

	/* the default response packet */
	ldns_pkt *req = srq->request;
	ldns_pkt *resp = srq->response = evldns_response(req, LDNS_RCODE_NOERROR);

	/* check DNSSEC flags */
	bool edns = ldns_pkt_edns(req);
	bool do_bit = edns && ldns_pkt_edns_do(req);

	/* if not, RCODE = REFUSED */
	if (is_top_domain) {
		parent_callback(resp, qname, qtype, qclass, do_bit);
	} else {
		child_callback(resp, qname, qtype, qclass, do_bit);
	}

	/* update packet header */
	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(ldns_pkt_answer(resp)));
	ldns_pkt_set_nscount(resp, ldns_rr_list_rr_count(ldns_pkt_authority(resp)));
	ldns_pkt_set_aa(resp, 1);

	/* request EDNS */
	ldns_pkt_set_edns_do(resp, do_bit);

	/* convert packet to wire format */
	(void) ldns_pkt2wire(&srq->wire_response, resp, &srq->wire_resplen);

	/* log it */
	char host[NI_MAXHOST], port[NI_MAXSERV];
	if (getnameinfo((sockaddr *)&srq->addr, srq->addrlen,
					host, sizeof(host),
					port, sizeof(port),
					NI_NUMERICHOST | NI_NUMERICSERV) != 0)
	{
		strcpy(host, "unknown");
		strcpy(port, "0");
	}

	ldns_buffer *qname_buf = ldns_buffer_new(256);
	ldns_rdf2buffer_str_dname(qname_buf, qname);
	char *qname_str = (char *)ldns_buffer_export(qname_buf);
	char *qclass_str = ldns_rr_class2str(qclass);
	char *qtype_str = ldns_rr_type2str(qtype);

	char logbuffer[2048];

	int n = snprintf(logbuffer, sizeof(logbuffer),
		"%ld.%06ld client %s#%s: query: %s %s %s %s%s%s%s%s (%s) %d %lu\n",
		(unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec,
		host, port,
		qname_str, qclass_str, qtype_str,
		ldns_pkt_rd(req) ? "+" : "-",		// RD
		edns ? "E" : "",					// EDNS
		srq->is_tcp ? "T": "",				// TCP
		do_bit ? "D": "",					// DO
		ldns_pkt_cd(req) ? "C" : "",		// CD
		"",									// RDATA - not supported
		ldns_pkt_get_rcode(resp),			// RCODE
		srq->wire_resplen
	);

	if (n < (int) sizeof(logbuffer)) {
		write(openlog(tv.tv_sec), logbuffer, n);
	}

	free(qname_str);
	free(qtype_str);
	free(qclass_str);
	ldns_buffer_free(qname_buf);
}

// --------------------------------------------------------------------

/* hook to handle calling the C++ member function */
void apnic_callback(evldns_server_request *srq, void *user_data,
				 ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	APNIC *apnic = static_cast<APNIC*>(user_data);
	apnic->callback(srq, qname, qtype, qclass);
}

/* rejects packets that arrive malformed */
void query_check(evldns_server_request *srq, void* /* user_data */,
				 ldns_rdf* /* qname */, ldns_rr_type qtype, ldns_rr_class qclass)
{
	ldns_pkt *req = srq->request;

	/* only QUERY is supported */
	if (ldns_pkt_get_opcode(req) != LDNS_PACKET_QUERY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* QDCOUNT == 1, NB: QDCOUNT == 1 now handled upstream */
	if (ldns_pkt_qdcount(req) != 1) {
		srq->response = evldns_response(req, LDNS_RCODE_FORMERR);
		return;
	}

	/* Unexpected QCLASS */
	if (qclass != LDNS_RR_CLASS_IN) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* Unexpected QTYPE */
	if (qtype == LDNS_RR_TYPE_AXFR || qtype == LDNS_RR_TYPE_IXFR) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* Not going to handle QTYPE == ANY either */
	if (qtype == LDNS_RR_TYPE_ANY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}
}

void* thread_dispatch(void *ptr)
{
	(void)event_base_dispatch(reinterpret_cast<event_base *>(ptr));
	return NULL;
}

void* orphan_dispatch(void *ptr)
{
	APNIC *state = reinterpret_cast<APNIC *>(ptr);

	while (1) {
		sleep(1);
		state->kill_orphans();
	}

	return NULL;
}

#if MALLOC_DEBUG
void* memory_stats(void *)
{
	while (1) {
		malloc_stats();
		malloc_info(0, stderr);
		sleep(60);
	}

	return NULL;
}
#endif

// --------------------------------------------------------------------

pthread_mutex_t *locks;

void static_thread_id(CRYPTO_THREADID *id)
{
	CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}

void static_lock_function(int mode, int n, const char* /* file */, int /* line */)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&locks[n]);
	} else {
		pthread_mutex_unlock(&locks[n]);
	}
}

struct CRYPTO_dynlock_value {
	pthread_mutex_t		mutex;
};

CRYPTO_dynlock_value *dyn_create_function(const char* /* file */, int /* line */)
{
	CRYPTO_dynlock_value *lock = (CRYPTO_dynlock_value *)malloc(sizeof(*lock));
	pthread_mutex_init(&lock->mutex, NULL);
	return lock;
}

void dyn_lock_function(int mode, CRYPTO_dynlock_value *lock, const char* /* file */, int /* line */)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&lock->mutex);
	} else {
		pthread_mutex_unlock(&lock->mutex);
	}
}

void dyn_destroy_function(CRYPTO_dynlock_value *lock, const char* /* file */, int /* line */)
{
	pthread_mutex_destroy(&lock->mutex);
	free(lock);
}

void threadsafe_openssl()
{
	int n = CRYPTO_num_locks();
	locks = (pthread_mutex_t *)calloc(n, sizeof(pthread_mutex_t));
	for (int i = 0; i < n; ++i) {
		pthread_mutex_init(&locks[i], NULL);
	}

	CRYPTO_THREADID_set_callback(static_thread_id);
	CRYPTO_set_locking_callback(static_lock_function);

	// dynamic locking
	CRYPTO_set_dynlock_create_callback(dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
}

// --------------------------------------------------------------------


// --------------------------------------------------------------------

void instance(int threads, int *fds, APNIC *state)
{
	pthread_t	ptc, pts[threads];
#if MALLOC_DEBUG
	pthread_t	ptm;
#endif

	if (threads > 1) {
		threadsafe_openssl();
	}

	for (int t = 0; t < threads; ++t) {
		/* setup evldns once for each thread */
		event_base *base = event_base_new();
		evldns_server *p = evldns_add_server(base);
		evldns_add_server_ports(p, fds);

		/* register callbacks and start it all up */
		evldns_add_callback(p, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_check, NULL);
		evldns_add_callback(p, NULL, LDNS_RR_CLASS_IN, LDNS_RR_TYPE_ANY, apnic_callback, state);
		pthread_create(&pts[t], NULL, thread_dispatch, base);
	}

	pthread_create(&ptc, NULL, orphan_dispatch, state);
#if MALLOC_DEBUG
	pthread_create(&ptm, NULL, memory_stats, NULL);
#endif

	/* wait for all threads to finish (won't ever happen) */
	for (int t = 0; t < threads; ++t) {
		pthread_join(pts[t], NULL);
	}
}

// --------------------------------------------------------------------

int main(int argc, char *argv[])
{
	argc--;
	argv++;

	char default_host[] = "127.0.0.1";
	char default_port[] = "53";

	const char *host = default_host;
	const char *port = default_port;
	const char *dom = "";
	const char *par = "";
	const char *chi = "";	/* ty-loc-zonefile */
	const char *key = "";
	const char *logpath = "./queries-%F.log";
	int			threads = 1;
	int			forx = 1;

	while (argc > 0 && **argv=='-') {

		char o = *++*argv;

		switch (o) {
			case 'h': argc--; argv++; host = *argv; break;
			case 'd': argc--; argv++; dom = *argv; break;
			case 'p': argc--; argv++; par = *argv; break;
			case 'c': argc--; argv++; chi = *argv; break;
			case 'k': argc--; argv++; key = *argv; break;
			case 't': argc--; argv++; threads = atoi(*argv); break;
			case 'P': argc--; argv++; port = *argv; break;
			case 'n': argc--; argv++; forx = atoi(*argv); break;
			case 'l': argc--; argv++; logpath = *argv; break;
			default: exit(1);
		}
		argc--;
		argv++;
	}

	/* single set of FDs shared by all threads */
	int *fds = bind_to_all(host, port, 1024);

	/* TODO - drop privs here if running as root */

	/* single state object shared by all threads */
	APNIC state(dom, key, par, chi, logpath);

	/* now we fork a farm */
	if (forx > 1) {
		for (int forxed = 0; forxed < forx; forxed++) {
			pid_t pid = fork();
			if (pid == 0) {
				instance(threads, fds, &state);
			} else if (pid > 0) {
				fprintf(stdout, "fork(%d)\n", pid);
			} else {
				fprintf(stdout, "fork() failed!\n");
				return EXIT_FAILURE;
			}
		}
		// parent, wait for children
		while (wait(NULL) > 0);

	} else {
		instance(threads, fds, &state);
	}

	return EXIT_SUCCESS;
}
