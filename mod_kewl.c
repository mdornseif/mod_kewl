/*  $Id: mod_kewl.c,v 1.1 2000/08/16 15:53:47 drt Exp $ 
**  mod_kewl.c -- Apache kewl module
**
**  based on mod_layout by Brian <brian@tangent.org>
**
**  To use: 
**  $ cd APACHEDIR; ./configure -add-module=~/mod_kewl.c
**
**  $Log: mod_kewl.c,v $
**  Revision 1.1  2000/08/16 15:53:47  drt
**  Initial revision
**
*/

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "alloc.h"
#include "fnmatch.h"

#define BUFFER_LENGTH 1024
#define UNSET (-1)
#define OFF (0)
#define ON (1)

typedef struct {
	int proxy;
	int glob;
	int http_header_enabled;
	int comment;
	/* These next two variables change with each request */
	int request_header;
	int request_footer;
	char *http_header;
	char *time_format;
	char *header;
	char *footer;
	table *types;
	table *uris_ignore;
	table *uris_ignore_header;
	table *uris_ignore_footer;
} kewl_conf;


module MODULE_VAR_EXPORT kewl_module;

static void *create_dir_mconfig(pool *p, char *dir)
{
/* So why -1, 0, and 1?  You see, C lacks an arithmatic if. We need to
	know three states at any point. We need to know if something is unset, off or
	on. Hence we use these values. Apache already understands Off as 0 and 1 as
	on. 
*/
	kewl_conf *cfg;
	cfg = ap_pcalloc(p, sizeof(kewl_conf));
	cfg->proxy = UNSET;
	cfg->comment = UNSET;
	cfg->glob = UNSET;
	cfg->http_header_enabled = UNSET;
	cfg->http_header = NULL;
	cfg->header = NULL;
	cfg->footer = NULL;
	cfg->request_header = OFF;
	cfg->time_format = NULL;
	cfg->types = ap_make_table(p, 8);
	cfg->uris_ignore = ap_make_table(p, 8);

	ap_table_set(cfg->types, INCLUDES_MAGIC_TYPE, "1");
	ap_table_set(cfg->types, INCLUDES_MAGIC_TYPE3, "1");
	ap_table_set(cfg->types, "server-parsed", "1");
	ap_table_set(cfg->types, "text/html", "1");
	ap_table_set(cfg->types, "text/plain", "1");
	ap_table_set(cfg->types, "perl-script", "1");
	ap_table_set(cfg->types, "cgi-script", "1");
	ap_table_set(cfg->types, "application/x-httpd-cgi", "1");

	return (void *) cfg;
}

static void *merge_dir_mconfig(pool *p, void *origin, void *new) {
	kewl_conf *cfg = ap_pcalloc(p, sizeof(kewl_conf));
	kewl_conf *cfg_origin = (kewl_conf *)origin;
	kewl_conf *cfg_new = (kewl_conf *)new;
	cfg->proxy = UNSET;
	cfg->comment = UNSET;
	cfg->glob = UNSET;
	cfg->http_header_enabled = UNSET;
	cfg->http_header = NULL;
	cfg->request_header = OFF;
	cfg->request_footer = OFF;
	
	
	cfg->proxy = (cfg_new->proxy == UNSET) ? cfg_origin->proxy : cfg_new->proxy;
	cfg->comment = (cfg_new->comment == UNSET) ? cfg_origin->comment : cfg_new->comment;
	cfg->glob = (cfg_new->glob == UNSET) ? cfg_origin->glob : cfg_new->glob;
	if(cfg_new->http_header_enabled == UNSET){
		cfg->http_header = ap_pstrdup(p, cfg_origin->http_header);
		cfg->http_header_enabled = cfg_origin->http_header_enabled;
	} else if (cfg_new->http_header_enabled == ON){
		cfg->http_header = ap_pstrdup(p, cfg_new->http_header);
		cfg->http_header_enabled = cfg_new->http_header_enabled;
	} else {
		cfg->http_header_enabled = OFF;
	}

	cfg->types = ap_overlay_tables(p, cfg_new->types, cfg_origin->types);
	cfg->uris_ignore = ap_overlay_tables(p, cfg_new->uris_ignore, cfg_origin->uris_ignore);

	return (void *) cfg;
}

int check_table(const char *a) {
	if (a == NULL) 
		return 0;
	if('1' == a[0])
		return 1;

	return 0;
}

/* This method is borrowed from alloc.c in the main apache 
	 distribution. */

int table_find(const table * t, const char *key) {
	array_header *hdrs_arr = ap_table_elts(t);
	table_entry *elts = (table_entry *) hdrs_arr->elts;
	int i;

	if (key == NULL)
		return 0;

	for (i = 0; i < hdrs_arr->nelts; ++i) {
		if (!ap_fnmatch(elts[i].key, key, FNM_PATHNAME | FNM_CASE_BLIND))
			if(check_table(elts[i].val))
				return 1;
	}


	return 0;
}

/* this is our workhorse */
static int kewl_handler(request_rec * r) {

/*
 * Default handler for MIME types without other handlers.  Only GET
 * and OPTIONS at this point... anyone who wants to write a generic
 * handler for PUT or POST is free to do so, but it seems unwise to provide
 * any defaults yet... So, for now, we assume that this will always be
 * the last handler called and return 405 or 501.
 */

    int rangestatus, errstatus;
    FILE *f;
    caddr_t mm;
    int convert_flag;
    int status;
    int assbackwards;
    kewl_conf *cfg;
    const char *content_length = NULL;
    
    if (r->main) 
      {
	return DECLINED;
      }
    
    cfg = ap_get_module_config(r->per_dir_config, &kewl_module);
    
    r->allowed |= (1 << M_GET) | (1 << M_OPTIONS);
    
    if (r->method_number == M_INVALID) 
	  {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
					  "Invalid method in request %s", r->the_request);
		return NOT_IMPLEMENTED;
	  }

    if (r->method_number == M_OPTIONS)
	  return ap_send_http_options(r);
	 
    if (r->method_number == M_PUT) 
      return METHOD_NOT_ALLOWED;
    
    if (r->finfo.st_mode == 0 || (r->path_info && *r->path_info)) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r,
					"File does not exist: %s",r->path_info ?
					ap_pstrcat(r->pool, r->filename, r->path_info, NULL)
					: r->filename);
      return HTTP_NOT_FOUND;
    }

    if (r->method_number != M_GET) 
	  return METHOD_NOT_ALLOWED;
	
	
#if defined(OS2) || defined(WIN32) || defined(NETWARE)
    /* Need binary mode for OS/2 */
    f = ap_pfopen(r->pool, r->filename, "rb");
#else
    f = ap_pfopen(r->pool, r->filename, "r");
#endif
	
    if (f == NULL) 
	  {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
					  "file permissions deny server access: %s", r->filename);
		return FORBIDDEN;
	  }
    
    ap_update_mtime(r, r->finfo.st_mtime);
    ap_set_last_modified(r);
    /* what was this etag for?   ap_set_etag(r); */
    if (((errstatus = ap_meets_conditions(r)) != OK)
	|| (errstatus = ap_set_content_length(r, r->finfo.st_size))) 
      return errstatus;
    
	/* here we go */
    ap_send_http_header(r);
    
	/* we should never get a header ony request, but better be sure */
    if (!r->header_only) 
      {
		char ibuf[IOBUFSIZE];
		char obuf[IOBUFSIZE*2];
		long total_bytes_sent = 0;
		int n, i, o, len;
		int intag = 0;
				
		len = IOBUFSIZE;
		o = 0;
		
		while (!r->connection->aborted) {
		  while ((n = fread(ibuf, sizeof(char), len, f)) < 1
				 && ferror(f) && errno == EINTR && !r->connection->aborted)
            continue;
		  
		  if (n < 1) {
            break;
		  }
		  
		  for(i = 0; i < n; i++)
			{
			  // I'm ugly, fat and non-functional ... mmap night help to relive pain?
			  
			  if(o < IOBUFSIZE)
				{ 
				  // Flush outputbuffer
				  ap_rwrite(obuf, o, r);
				  o = 0;
				}
			  
			  if(ibuf[i] == '<') intag++;
			  if(ibuf[i] == '>') intag--;
			  
			  if(intag)
				obuf[o++] = ibuf[i];
			  else
				switch(ibuf[i])
				  {
				  case 'O':
				  case 'o': obuf[o++] = '0'; break;
				  case 'i': obuf[o++] = '1'; break;
				  case 'L': case 'l': obuf[o++] = '7'; break;
				  case 'E': case 'e': obuf[o++] = '3'; break;
				  case 'Z': case '2': obuf[o++] = '2'; break;
				  case 'F': obuf[o++] = 'P'; obuf[o++] = 'h'; break;
				  case 'f': obuf[o++] = 'p'; obuf[o++] = 'h'; break;
				  case 'S': obuf[o++] = '$'; break;
				  case 's': 
					if((i < len-1) && 
					   (ibuf[i+1] == ' ' || ibuf[i+1] == '.' 
						|| ibuf[i+1] == ',' || ibuf[i+1] == '\n' 
						|| ibuf[i+1] == '<'))  
					  obuf[o++] = 'z';
					else
					  obuf[o++] = '5'; 
					break;   
				  default: obuf[o++] = ibuf[i];
				  }
			}
		  if(o > 0)
			{ 
			  // Flush outputbuffer
			  ap_rwrite(obuf, o, r);
			}
		}
      }
    ap_pfclose(r->pool, f);
    return OK;
}

static int kewl_fixup(request_rec *r) {
	kewl_conf *cfg = ap_get_module_config(r->per_dir_config, &kewl_module);
	request_rec *subr;
	char *type = NULL;

	if (r->main) 
		return DECLINED;

	/* If this is a HEAD only, we really don't need to involve ourselves. */
	if (r->header_only) 
		return DECLINED;

	/* So why switch to doing this? Somewhere since 1.3.6 something
		 has changed about the way that CGI's are done. Not sure what
		 it is, but this is now needed */
	/* First, we check to see if this is SSI, mod_perl or cgi */
	if(r->handler) 
	  type = ap_pstrdup(r->pool, r->handler);
	else 
	  type = ap_pstrdup(r->pool, r->content_type);
	
	if ((cfg->proxy > OFF) && r->proxyreq) 
	  {
		/* proxy request */
		
		/* 
		   Damn! Ok, here is the problem. If the request is for something
		   which is and index how do we determine its mime type? Currently
		   we just assume that it is a NULL and wrap it. This is far
		   from perfect and is still pretty much a shot in the dark.
		   More research needed.
		*/
		subr = (request_rec *) ap_sub_req_lookup_file(r->uri, r);
		type = ap_pstrdup(r->pool, subr->content_type);
		ap_destroy_sub_req(subr);
		if (cfg->glob > OFF)
		  {
			if (!table_find(cfg->types, type) && r->content_type != NULL)
			  return DECLINED;
		  } 
		else 
		  {
			if (!check_table(ap_table_get(cfg->types, type)) && r->content_type != NULL)
			  return DECLINED;
		  }
	  } 
	else
	  {
		/* regular request */
		if (cfg->glob > OFF)
		  {
			if (!table_find(cfg->types, type))
			  return DECLINED;
		  } 
		else 
		  {
			if (!check_table(ap_table_get(cfg->types, type))) 
			  return DECLINED;
		  }
	  }

	/* Now lets look at the ignore logic */
	/* This is where we finally decide what is going to happen */
	if (table_find(cfg->uris_ignore, r->uri))
	  return DECLINED;	
	
	/* Now, lets fix it if some goof has called a URL that 
	   should have had a / in it */
	if(ap_is_directory(r->filename)) {
	  if(r->uri[0] == '\0' || r->uri[strlen(r->uri) - 1] != '/') {
		/* Now at this point we know things are not going to
		   go over well, so lets just let it all die in some module
		   designed to take care of this sort of thing */
		return DECLINED;
	  }
	}
	r->handler = "kewl";
	
	return DECLINED;
}

/* Dispatch list of content handlers */
static const handler_rec kewl_handlers[] = {
	{"kewl", kewl_handler},
	{NULL}
};

static const char *ignore_uri(cmd_parms * cmd, void *mconfig, char *uri) {
	kewl_conf *cfg = (kewl_conf *) mconfig;
	ap_table_set(cfg->uris_ignore, uri, "1");

	return NULL;
}

static const char *add_type(cmd_parms * cmd, void *mconfig, char *type) {
	kewl_conf *cfg = (kewl_conf *) mconfig;
	ap_table_set(cfg->types, type, "1");

	return NULL;
}

static const char *http_header_off(cmd_parms * cmd, void *mconfig) {
	kewl_conf *cfg = (kewl_conf *) mconfig;
	cfg->header = NULL;
	cfg->http_header_enabled = OFF;

	return NULL;
}

static const char *remove_default_types(cmd_parms * cmd, void *mconfig, int flag) {
	kewl_conf *cfg = (kewl_conf *) mconfig;
	if (flag)
		return NULL;

	ap_table_set(cfg->types, INCLUDES_MAGIC_TYPE, "0");
	ap_table_set(cfg->types, INCLUDES_MAGIC_TYPE3, "0");
	ap_table_set(cfg->types, "server-parsed", "0");
	ap_table_set(cfg->types, "text/html", "0");
	ap_table_set(cfg->types, "text/plain", "0");
	ap_table_set(cfg->types, "perl-script", "0");
	ap_table_set(cfg->types, "cgi-script", "0");
	ap_table_set(cfg->types, "application/x-httpd-cgi", "0");

	return NULL;
}

static const command_rec kewl_cmds[] = {
	{"KewlHandler", add_type, NULL, OR_ALL, TAKE1, 
	 "Enter either a mime type or a handler type."},
	{"KewlIgnoreURI", ignore_uri, NULL, OR_ALL, TAKE1,
	 "Enter URI that should be ignored, regular expressions are allowed."},
	{"KewlHandlerGlob", ap_set_flag_slot, (void *) XtOffsetOf(kewl_conf, glob), OR_ALL, FLAG, 
	 "This can either be On or Off (default it Off)."},
	{"KewlProxy", ap_set_flag_slot, (void *) XtOffsetOf(kewl_conf, proxy), OR_ALL, FLAG, 
	 "This can either be On or Off (default it Off)."},
	{"KewlDefaultHandlers", remove_default_types, NULL, OR_ALL, FLAG,
	 "Turns On (default) or Off a list of standard types to handle."},
	{"KewlHTTPHeaderOff", http_header_off, NULL, OR_ALL, NO_ARGS, 
	 "This takes no arguments. If found it will turn off the http header."},
	{NULL},
};

static void kewl_init(server_rec * s, pool * p) {
	/* Tell apache we're here */
	ap_add_version_component("m0d_k3wl/0.0.17");
}

/* Dispatch list for API hooks */
module MODULE_VAR_EXPORT kewl_module = {
	STANDARD_MODULE_STUFF,
	kewl_init,					   	/* module initializer                  */
	create_dir_mconfig,				/* create per-dir    config structures */
	merge_dir_mconfig,  			/* merge  per-dir    config structures */
	NULL,			   				/* create per-server config structures */
	NULL,						   	/* merge  per-server config structures */
	kewl_cmds,						/* table of config file commands       */
	kewl_handlers,					/* [#8] MIME-typed-dispatched handlers */
	NULL,			   				/* [#1] URI to filename translation    */
	NULL,						 	/* [#4] validate user id from request  */
	NULL,			   				/* [#5] check if the user is ok _here_ */
	NULL,  							/* [#3] check access by host address   */
	NULL,			   				/* [#6] determine MIME type            */
	kewl_fixup,		  				/* [#7] pre-run fixups                 */
	NULL,  							/* [#9] log a transaction              */
	NULL,					   		/* [#2] header parser                  */
	NULL,		   					/* child_init                          */
	NULL,	 				   		/* child_exit                          */
	NULL		   					/* [#0] post read-request              */
};
