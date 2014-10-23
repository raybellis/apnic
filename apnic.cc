/*
 * $Id: $
 *
 * Copyright (c) 2014, Nominet UK.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *	 * Neither the name of Nominet UK nor the names of its contributors may
 *	   be used to endorse or promote products derived from this software
 *	   without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY Nominet UK ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Nominet UK BE LIABLE FOR ANY
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
	bool							 is_signed;
	bool							 is_broken;

private:
	ldns_rdf						*origin;
	int								 origin_count;
	ldns_dnssec_zone				*parent_zone;
	ChildMap						 children;

private:
	void kill_orphans();
	ldns_dnssec_zone *load_zone(ldns_rdf *origin, string zonefile);
	void sign_zone(ldns_dnssec_zone *zone, ldns_key_list *keys);
	ldns_key_list *create_signing_key(ldns_rdf *origin);
	void create_parent_zone();
	APZone *create_child_zone(ldns_rdf *origin);

	void zone_lookup(ldns_pkt *resp, ldns_dnssec_zone *zone, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit);
	void synthesize_ds_record(ldns_pkt *resp, ldns_rdf *qname, APZone *apz, bool do_bit);
	void parent_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit);
	void child_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit);

public:
	APNIC(string domain, string keyfile, string parentfile, string childfile, bool is_signed = false, bool is_broken = false);
	~APNIC();

public:
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

APNIC::APNIC(string domain, string key_file, string parent_file, string child_file, bool is_signed, bool is_broken)
: key_file(key_file), parent_file(parent_file), child_file(child_file), is_signed(is_signed), is_broken(is_broken)
{
	origin = ldns_dname_new_frm_str(domain.c_str());
	origin_count = ldns_dname_label_count(origin);

	create_parent_zone();
}

APNIC::~APNIC()
{
	ldns_dnssec_zone_deep_free(parent_zone);
	ldns_rdf_deep_free(origin);
}

ldns_key_list *APNIC::create_signing_key(ldns_rdf *origin)
{
	FILE *fp = fopen(key_file.c_str(), "r");
	if (!fp) {
		throw std::runtime_error("popen: " + string(strerror(errno)));
	}

	ldns_key *key;
	ldns_status status = ldns_key_new_frm_fp(&key, fp);
	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("error loading key file: " + string(ldns_get_errorstr_by_id(status)));
	}
	fclose(fp);

	ldns_key_list *list = ldns_key_list_new();
	ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));
	ldns_key_list_push_key(list, key);

	return list;
}

ldns_dnssec_zone *APNIC::load_zone(ldns_rdf *origin, string zonefile)
{
	ldns_dnssec_zone *zone;

	/* load zone file */
	FILE *fp = fopen(zonefile.c_str(), "r");
	if (!fp) {
		throw std::runtime_error("popen: " + string(strerror(errno)));
	}
	ldns_status status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin, 60, LDNS_RR_CLASS_IN);
	fclose(fp);

	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("error loading zone file: " + string(ldns_get_errorstr_by_id(status)));
	}

	return zone;
}

void APNIC::sign_zone(ldns_dnssec_zone *zone, ldns_key_list *keys)
{
	/* add them to the zone */
	for (int i = 0, n = ldns_key_list_key_count(keys); i < n; ++i) {
		ldns_rr *rr = ldns_key2rr(ldns_key_list_key(keys, i));
		ldns_dnssec_zone_add_rr(zone, rr);
	}

	/* and sign it */
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
	if (is_signed) {
		ldns_key_list *parent_keys = create_signing_key(this->origin);
		sign_zone(parent_zone, parent_keys);
		ldns_key_list_free(parent_keys);
	}
}

APZone *APNIC::create_child_zone(ldns_rdf *origin)
{
	/* create the child zone */
	ldns_dnssec_zone *child_zone = load_zone(origin, child_file);
	if (!is_signed) {
		return new APZone(child_zone, NULL, NULL);
	}

	/* sign the child zone */
	ldns_key_list *child_keys = create_signing_key(origin);
	sign_zone(child_zone, child_keys);

	/* create a list of DS record for this child, relying on key's public
	   owner being set by previous function */
	ldns_rr_list *ds_list = ldns_rr_list_new();
	for (int i = 0, n = ldns_key_list_key_count(child_keys); i < n; ++i) {
		ldns_rr *key_rr = ldns_key2rr(ldns_key_list_key(child_keys, i));
		ldns_rr *ds = ldns_key_rr2ds(key_rr, LDNS_SHA1);

		/* if required, change the DS record RDATA so it doesn't actually
		   match the given key, breaking the signature chain */
		if (is_broken) {
			ldns_rdf *rdata = ldns_rr_rdf(ds, 0);
			uint8_t *raw = ldns_rdf_data(rdata);
			raw[0] = ~raw[0]; /* Key Tag MSB */
			raw[1] = ~raw[1]; /* Key Tag LSB */
			raw[4] = ~raw[4]; /* Digest[0] */
		}

		ldns_rr_list_push_rr(ds_list, ds);
		ldns_rr_free(key_rr);
	}

	/* child keys no longer required */
	ldns_key_list_free(child_keys);

	/* create RRSIGs over the DS - NB: requires the parent origin */
	ldns_key_list *parent_keys = create_signing_key(this->origin);
	ldns_rr_list *ds_rrsig = ldns_sign_public(ds_list, parent_keys);
	ldns_key_list_free(parent_keys);

	return new APZone(child_zone, ds_list, ds_rrsig);
}

void APNIC::zone_lookup(ldns_pkt *resp, ldns_dnssec_zone *zone, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit)
{
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

void APNIC::synthesize_ds_record(ldns_pkt *resp, ldns_rdf *qname, APZone *apz, bool do_bit)
{
	ldns_rr_list *answer = ldns_pkt_answer(resp);

	/* add the DS rr_list to the answer */
	rr_list_cat_rr_list_clone(answer, apz->ds);

	/* include RRSIG over the DS, if required */
	if (do_bit) {
		rr_list_cat_rr_list_clone(answer, apz->ds_rrsig);
	}
}

void APNIC::kill_orphans()
{
	/* what time is it? */
	time_t now = time((time_t)0);
	time_t then = now - 60;

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
}

void APNIC::child_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass, bool do_bit)
{
	/* extract the subdomain name, based on the last label before the parent */
	int qname_count = ldns_dname_label_count(qname);
	int label_count = qname_count - origin_count;
	ldns_rdf *child = ldns_dname_clone_from(qname, label_count - 1);

	/* look up the zone from cache, or create a new one */
	APZone *apz;
	ChildMap::iterator it = children.find(child);
	if (it == children.end()) {
		ldns_rdf *child_origin = ldns_rdf_clone(child);
		children[child_origin] = apz = create_child_zone(child_origin);
	} else {
		apz = it->second;
	}
 
	/* pretend to be the parent zone if asking for a DS record */
	if (label_count == 1 && qtype == LDNS_RR_TYPE_DS) {
		synthesize_ds_record(resp, child, apz, do_bit);
	} else {
		zone_lookup(resp, apz->zone, qname, qtype, qclass, do_bit);
	}

	ldns_rdf_deep_free(child);
}

void APNIC::callback(evldns_server_request *srq,
				 ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	/* log request time for later */
	timeval tv;
	gettimeofday(&tv, NULL);

	/* expire old zone data */
	kill_orphans();

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
	ldns_status status = ldns_pkt2wire(&srq->wire_response, resp, &srq->wire_resplen);

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
	char *qclass_str = ldns_rr_class2str(qclass);
	char *qtype_str = ldns_rr_type2str(qtype);

	fprintf(stdout,
		"%ld.%06ld client %s#%s: query: %s %s %s %s%s%s%s %d %d\n",
		tv.tv_sec, tv.tv_usec,
		host, port,
		 ldns_buffer_export(qname_buf), qclass_str, qtype_str,
		ldns_pkt_rd(req) ? "+" : "-",		// RD
		edns ? "E" : "",					// EDNS
		do_bit ? "D": "",					// DO
		ldns_pkt_cd(req) ? "C" : "",		// CD
		ldns_pkt_get_rcode(resp),
		srq->wire_resplen
	);

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
void query_check(evldns_server_request *srq, void *user_data,
				 ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	ldns_pkt *req = srq->request;

	/* only QUERY is supported */
	if (ldns_pkt_get_opcode(req) != LDNS_PACKET_QUERY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* QR == 1 && QDCOUNT == 1 */
	if (ldns_pkt_qr(req) || ldns_pkt_qdcount(req) != 1) {
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

// --------------------------------------------------------------------

int main(int argc, char *argv[])
{
	/* objects to hold zone state */
	APNIC apnic_unsigned("u.example.com.", "data/dnskey", "data/zone.parent", "data/zone.child", false, false);
	APNIC apnic_invalid("v.example.com.", "data/dnskey", "data/zone.parent", "data/zone.child", true, true);
	APNIC apnic_valid("w.example.com.", "data/dnskey", "data/zone.parent", "data/zone.child", true, false);

	/* setup evldns */
	event_init();
	evldns_server *p = evldns_add_server();
	evldns_add_server_port(p, bind_to_udp4_port(53));
	evldns_add_server_port(p, bind_to_tcp4_port(53, 10));

	/* TODO - drop privs here if running as root */

	/* register callbacks and start it all up */
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_check, NULL);
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_IN, LDNS_RR_TYPE_ANY, apnic_callback, &apnic_unsigned);
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_IN, LDNS_RR_TYPE_ANY, apnic_callback, &apnic_invalid);
	evldns_add_callback(p, NULL, LDNS_RR_CLASS_IN, LDNS_RR_TYPE_ANY, apnic_callback, &apnic_valid);
	event_dispatch();

	return EXIT_SUCCESS;
}
