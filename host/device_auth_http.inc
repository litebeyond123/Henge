/* Included after share.c's bounded HTTP/body helpers. JSON stays deliberately
   flat: there is no raw-message/event passthrough into a diagnostic report. */
typedef struct {
    unsigned fields;
    char operation[32], launch[37], request[37], stage[64], domain[128];
    long long protocol, error_code, elapsed_ms, input_bytes, result_bytes, target_pid, observed_pid;
    long long process_phase, process_source, process_state, process_flags, process_status, process_retries,
        process_sample_ms, operation_invoked, operation_result, phase_elapsed_ms;
} AuthJSON;

enum {
    AJ_PROTOCOL=1u<<0, AJ_OPERATION=1u<<1, AJ_LAUNCH=1u<<2, AJ_REQUEST=1u<<3,
    AJ_PAYLOAD=1u<<4, AJ_STAGE=1u<<5, AJ_DOMAIN=1u<<6, AJ_CODE=1u<<7,
    AJ_ELAPSED=1u<<8, AJ_INPUT=1u<<9, AJ_RESULT=1u<<10, AJ_TARGET_PID=1u<<11, AJ_OBSERVED_PID=1u<<12,
    AJ_PHASE=1u<<13, AJ_SOURCE=1u<<14, AJ_STATE=1u<<15, AJ_FLAGS=1u<<16, AJ_STATUS=1u<<17,
    AJ_RETRIES=1u<<18, AJ_SAMPLE_MS=1u<<19, AJ_INVOKED=1u<<20, AJ_OPERATION_RESULT=1u<<21, AJ_PHASE_MS=1u<<22,
    AJ_PROCESS=AJ_PHASE|AJ_SOURCE|AJ_STATE|AJ_FLAGS|AJ_STATUS|AJ_RETRIES|AJ_SAMPLE_MS|AJ_INVOKED|AJ_OPERATION_RESULT|AJ_PHASE_MS
};

static int auth_string(const char **cursor, char *out, size_t cap, int base64) {
    const char *p=*cursor;
    if (*p++!='"') return 0;
    size_t n=0;
    while (*p && *p!='"') {
        unsigned char c=(unsigned char)*p++;
        if (c=='\\') { c=(unsigned char)*p++; if (c!='/' && c!='\\' && c!='"') return 0; }
        if (c<32 || c>126) return 0;
        if (base64 && !((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='=')) return 0;
        if (++n>=cap) return 0;
        if (out) out[n-1]=(char)c;
    }
    if (*p++!='"') return 0;
    if (out) out[n]=0;
    *cursor=p; return 1;
}

static int auth_integer(const char **cursor, long long *out) {
    const char *p=*cursor, *start=p;
    if (*p=='-') p++;
    if (*p=='0') p++;
    else { if (*p<'1'||*p>'9') return 0; while (*p>='0'&&*p<='9') p++; }
    char *end=NULL; errno=0;
    long long value=strtoll(start,&end,10);
    if (errno || p!=end) return 0;
    *out=value; *cursor=p; return 1;
}

static int auth_json(const char *json, AuthJSON *out, int event) {
    memset(out,0,sizeof *out);
    const char *p=host_json_space(json);
    if (*p++!='{') return 0;
    for (;;) {
        p=host_json_space(p);
        char key[32];
        if (!auth_string(&p,key,sizeof key,0)) return 0;
        p=host_json_space(p); if (*p++!=':') return 0; p=host_json_space(p);
        unsigned bit=0; char *target=NULL; size_t limit=0; long long *number=NULL;
        if (!strcmp(key,"protocol")) { bit=AJ_PROTOCOL; number=&out->protocol; }
        else if (!strcmp(key,"operation")) { bit=AJ_OPERATION; target=out->operation; limit=sizeof out->operation; }
        else if (!strcmp(key,"launch_id")) { bit=AJ_LAUNCH; target=out->launch; limit=sizeof out->launch; }
        else if (!strcmp(key,"request_id")) { bit=AJ_REQUEST; target=out->request; limit=sizeof out->request; }
        else if (!strcmp(key,"payloadBase64")) { bit=AJ_PAYLOAD; limit=48u*1024u; }
        else if (!strcmp(key,"stage")) { bit=AJ_STAGE; target=out->stage; limit=sizeof out->stage; }
        else if (!strcmp(key,"errorDomain")) { bit=AJ_DOMAIN; target=out->domain; limit=sizeof out->domain; }
        else if (!strcmp(key,"errorCode")) { bit=AJ_CODE; number=&out->error_code; }
        else if (!strcmp(key,"elapsedMs")) { bit=AJ_ELAPSED; number=&out->elapsed_ms; }
        else if (!strcmp(key,"inputBytes")) { bit=AJ_INPUT; number=&out->input_bytes; }
        else if (!strcmp(key,"resultBytes")) { bit=AJ_RESULT; number=&out->result_bytes; }
        else if (!strcmp(key,"targetPid")) { bit=AJ_TARGET_PID; number=&out->target_pid; }
        else if (!strcmp(key,"observedPid")) { bit=AJ_OBSERVED_PID; number=&out->observed_pid; }
        else if (!strcmp(key,"processPhase")) { bit=AJ_PHASE; number=&out->process_phase; }
        else if (!strcmp(key,"processSource")) { bit=AJ_SOURCE; number=&out->process_source; }
        else if (!strcmp(key,"processState")) { bit=AJ_STATE; number=&out->process_state; }
        else if (!strcmp(key,"processFlags")) { bit=AJ_FLAGS; number=&out->process_flags; }
        else if (!strcmp(key,"processStatus")) { bit=AJ_STATUS; number=&out->process_status; }
        else if (!strcmp(key,"processRetries")) { bit=AJ_RETRIES; number=&out->process_retries; }
        else if (!strcmp(key,"processSampleMs")) { bit=AJ_SAMPLE_MS; number=&out->process_sample_ms; }
        else if (!strcmp(key,"operationInvoked")) { bit=AJ_INVOKED; number=&out->operation_invoked; }
        else if (!strcmp(key,"operationResult")) { bit=AJ_OPERATION_RESULT; number=&out->operation_result; }
        else if (!strcmp(key,"phaseElapsedMs")) { bit=AJ_PHASE_MS; number=&out->phase_elapsed_ms; }
        else return 0;
        if (out->fields&bit) return 0;
        out->fields|=bit;
        if (number ? !auth_integer(&p,number) : !auth_string(&p,target,limit,bit==AJ_PAYLOAD)) return 0;
        p=host_json_space(p);
        if (*p=='}') { p=host_json_space(p+1); if (*p) return 0; break; }
        if (*p++!=',') return 0;
    }
    unsigned required=AJ_PROTOCOL|AJ_LAUNCH|AJ_REQUEST|(event?AJ_STAGE:AJ_OPERATION);
    unsigned allowed=required|(event?(AJ_DOMAIN|AJ_CODE|AJ_ELAPSED|AJ_INPUT|AJ_RESULT|AJ_TARGET_PID|AJ_OBSERVED_PID|AJ_PROCESS):AJ_PAYLOAD);
    if ((out->fields&required)!=required || (out->fields&~allowed) || out->protocol!=1 ||
        !host_uuid(out->launch) || !host_uuid(out->request)) return 0;
    if (event && (out->error_code<INT32_MIN || out->error_code>INT32_MAX || out->elapsed_ms<0 || out->elapsed_ms>300000 ||
        out->input_bytes<0 || out->input_bytes>HV_DEVICE_AUTH_BODY_MAX || out->result_bytes<0 || out->result_bytes>HV_DEVICE_AUTH_RESPONSE_MAX ||
        out->target_pid<0 || out->target_pid>INT32_MAX || out->observed_pid<0 || out->observed_pid>INT32_MAX)) return 0;
    if (out->fields & AJ_PROCESS) {
        if ((out->fields & AJ_PROCESS) != AJ_PROCESS ||
            out->process_phase<0 || out->process_phase>6 || out->process_source<0 || out->process_source>12 ||
            out->process_state<0 || out->process_state>4 || out->process_flags<0 || out->process_flags>15 ||
            out->process_status<0 || out->process_status>255 || out->process_retries<0 || out->process_retries>25 ||
            out->process_sample_ms<0 || out->process_sample_ms>300000 || out->phase_elapsed_ms<0 || out->phase_elapsed_ms>300000 ||
            out->operation_invoked<0 || out->operation_invoked>1 ||
            (!out->operation_invoked && out->operation_result!=-1) ||
            (out->operation_invoked && (out->operation_result<0 || out->operation_result>1))) return 0;
    }
    return 1;
}

static void auth_add_events(Text *json, const HvDeviceAuthEvent *events, size_t count) {
    for (size_t i=0;i<count;i++) {
        const HvDeviceAuthEvent *e=&events[i];
        if (i) adds(json,",");
        addf(json,"{\"sequence\":%llu,\"age_ms\":%llu,\"from_guest\":%s,\"request_id\":\"%s\",\"launch_id\":\"%s\","
            "\"stage\":\"%s\",\"errorDomain\":\"%s\",\"errorCode\":%lld,\"elapsedMs\":%u,\"inputBytes\":%u,\"resultBytes\":%u,\"targetPid\":%d,\"observedPid\":%d}",
            (unsigned long long)e->sequence,(unsigned long long)e->age_ms,e->from_guest?"true":"false",e->request_id,e->launch_id,
            hv_device_auth_stage_name(e->stage),hv_device_auth_domain_name(e->error_domain),(long long)e->error_code,
            e->elapsed_ms,e->input_bytes,e->result_bytes,e->target_pid,e->observed_pid);
    }
}

static char *auth_state_json(int supports_observed_exit) {
    HvDeviceAuthState state;
    hv_device_auth_snapshot(&state);
    /* Capability 4 includes observed process-exit handling. Older helpers must
       not claim either action; the host diagnostic view always sees real state. */
    if (!supports_observed_exit && state.enabled)
        return strdup("{\"protocol\":1,\"enabled\":false}\n");
    Text json={0};
    addf(&json,"{\"protocol\":1,\"session\":\"%s\",\"launch_id\":\"%s\",\"mode\":\"%s\",\"launch_action\":\"%s\","
        "\"enabled\":%s,\"running\":%s,\"foreground\":%s,\"fresh\":%s,\"active\":%s,\"busy\":%s,"
        "\"state_age_ms\":%lld,\"accepted_requests\":%llu,\"completed_requests\":%llu,\"refused_requests\":%llu,"
        "\"enable_attempts\":%llu,\"enable_successes\":%llu,\"enable_failures\":%llu,"
        "\"last_enable_error\":\"%s\",\"last_enable_mode\":\"%s\",\"last_enable_action\":\"%s\",\"backend_registered\":%s,\"last_enable_backend_registered\":%s,\"events\":[",
        state.session,state.launch_id,hv_device_auth_mode_name(state.mode),hv_device_auth_action_name(state.launch_action),state.enabled?"true":"false",state.running?"true":"false",
        state.foreground?"true":"false",state.fresh?"true":"false",state.active?"true":"false",state.busy?"true":"false",
        (long long)state.state_age_ms,(unsigned long long)state.accepted_requests,(unsigned long long)state.completed_requests,
        (unsigned long long)state.refused_requests,
        (unsigned long long)state.enable_attempts,(unsigned long long)state.enable_successes,(unsigned long long)state.enable_failures,
        state.enable_attempts?hv_device_auth_error_name(state.last_enable_error):"not_attempted",
        !state.enable_attempts?"not_attempted":state.last_enable_mode==HV_DEVICE_AUTH_MODE_NONE?"invalid":hv_device_auth_mode_name(state.last_enable_mode),
        !state.enable_attempts?"not_attempted":hv_device_auth_action_name(state.last_enable_action),
        state.backend_registered?"true":"false",state.last_enable_backend_registered?"true":"false");
    auth_add_events(&json,state.events,state.event_count);
    adds(&json,"],\"startup_events\":[");
    auth_add_events(&json,state.startup_events,state.startup_event_count);
    adds(&json,"],\"process_observation\":");
    const HvDeviceAuthEvent *e=&state.process_observation;
    const HvDeviceAuthProcessObservation *p=&e->process;
    if (!p->present) adds(&json,"null");
    else addf(&json,"{\"sequence\":%llu,\"age_ms\":%llu,\"launch_id\":\"%s\",\"stage\":\"%s\",\"elapsedMs\":%u,"
        "\"errorDomain\":\"%s\",\"errorCode\":%lld,\"targetPid\":%d,\"observedPid\":%d,"
        "\"processPhase\":%u,\"processSource\":%u,\"processState\":%u,\"processFlags\":%u,\"processStatus\":%u,"
        "\"processRetries\":%u,\"processSampleMs\":%u,\"operationInvoked\":%d,\"operationResult\":%d,\"phaseElapsedMs\":%u}",
        (unsigned long long)e->sequence,(unsigned long long)e->age_ms,e->launch_id,hv_device_auth_stage_name(e->stage),e->elapsed_ms,
        hv_device_auth_domain_name(e->error_domain),(long long)e->error_code,e->target_pid,e->observed_pid,
        p->phase,p->source,p->state,p->flags,p->status,p->retries,p->sample_ms,p->operation_invoked,p->operation_result,p->phase_elapsed_ms);
    adds(&json,",\"serverAcceptanceVerified\":false}\n");
    if (json.s && strlen(json.s)>HV_DEVICE_AUTH_STATE_RESPONSE_MAX) { free(json.s); return NULL; }
    return json.s;
}

char *hv_share_auth_state(void) { return auth_state_json(1); }

static int auth_service_error(Conn *c, Request *r, HvDeviceAuthError error) {
    return host_error(c,r,hv_device_auth_http_status(error),hv_device_auth_error_name(error));
}

static void auth_erase_free(void *data, size_t length) {
    volatile unsigned char *p=data; while (length--) *p++=0; free(data);
}

static int serve_device_auth(Conn *c, Request *r, const char *what) {
    int capability4=!strcmp(what,"state") && !strcmp(r->query,"capability=4");
    int legacy3=!strcmp(what,"state") && !strcmp(r->query,"capability=3");
    if (r->query[0] && !capability4 && !legacy3) return host_error(c,r,400,"unexpected_query");
    if (!strcmp(what,"state")) {
        if (strcmp(r->method,"GET")) return host_error(c,r,405,"get_required");
        if (r->length) return host_error(c,r,400,"unexpected_body");
        char *state=auth_state_json(capability4);
        if (!state) return host_error(c,r,503,"state_unavailable");
        int result=respond(c,r,200,"OK",host_json_headers,state,strlen(state));
        free(state); return result;
    }
    int event=!strcmp(what,"event");
    if (!event && strcmp(what,"request")) return host_error(c,r,404,"unknown_auth_route");
    if (strcmp(r->method,"POST")) return host_error(c,r,405,"post_required");
    if (!r->content_length_seen) return host_error(c,r,411,"content_length_required");
    size_t maximum=event?2048:HV_DEVICE_AUTH_BODY_MAX;
    if (r->length<=0 || (unsigned long long)r->length>maximum) return host_error(c,r,413,"body_size");
    if (strcasecmp(r->content_type,"application/json") && strcasecmp(r->content_type,"application/json; charset=utf-8"))
        return host_error(c,r,415,"application_json_required");
    if (!host_uuid(r->host_session)) return host_error(c,r,403,"session_required");
    size_t capacity=(size_t)r->length,used=0;
    char *body=malloc(capacity+1);
    if (!body) return host_error(c,r,503,"allocation_failed");
    body_ready(c,r);
    while (r->length>0) {
        ssize_t got=body_read(c,r,body+used,capacity-used);
        if (got<=0) { auth_erase_free(body,capacity+1); return host_error(c,r,400,"incomplete_body"); }
        used+=(size_t)got;
    }
    body[used]=0;
    AuthJSON values;
    if (memchr(body,0,used) || !auth_json(body,&values,event)) {
        auth_erase_free(body,capacity+1); return host_error(c,r,400,"invalid_auth_json");
    }
    if (event) {
        HvDeviceAuthEvent entry={0};
        memcpy(entry.request_id,values.request,sizeof entry.request_id);
        entry.stage=hv_device_auth_stage_from_name(values.stage);
        entry.error_domain=hv_device_auth_domain_from_name(values.domain);
        entry.error_code=values.error_code; entry.elapsed_ms=(uint32_t)values.elapsed_ms;
        entry.input_bytes=(uint32_t)values.input_bytes; entry.result_bytes=(uint32_t)values.result_bytes;
        entry.target_pid=(int32_t)values.target_pid; entry.observed_pid=(int32_t)values.observed_pid;
        if (values.fields & AJ_PROCESS) entry.process=(HvDeviceAuthProcessObservation){
            .present=1, .phase=(uint32_t)values.process_phase, .source=(uint32_t)values.process_source,
            .state=(uint32_t)values.process_state, .flags=(uint32_t)values.process_flags,
            .status=(uint32_t)values.process_status, .retries=(uint32_t)values.process_retries,
            .sample_ms=(uint32_t)values.process_sample_ms, .operation_invoked=(int)values.operation_invoked,
            .operation_result=(int)values.operation_result, .phase_elapsed_ms=(uint32_t)values.phase_elapsed_ms};
        HvDeviceAuthError error=hv_device_auth_record_event(r->host_session,values.launch,&entry);
        auth_erase_free(body,capacity+1);
        if (error!=HV_DEVICE_AUTH_OK) return auth_service_error(c,r,error);
        const char *answer="{\"protocol\":1,\"status\":\"ok\"}\n";
        return respond(c,r,200,"OK",host_json_headers,answer,strlen(answer));
    }
    HvDeviceAuthOperation operation;
    if (!strcmp(values.operation,"probe")) operation=HV_DEVICE_AUTH_PROBE;
    else if (!strcmp(values.operation,"dc_token")) operation=HV_DEVICE_AUTH_DC_TOKEN;
    else if (!strcmp(values.operation,"baa_data")) operation=HV_DEVICE_AUTH_BAA_DATA;
    else if (!strcmp(values.operation,"baa_dictionary")) operation=HV_DEVICE_AUTH_BAA_DICTIONARY;
    else { auth_erase_free(body,capacity+1); return host_error(c,r,400,"invalid_auth_operation"); }
    if (((values.fields&AJ_PAYLOAD)!=0)!=(operation==HV_DEVICE_AUTH_BAA_DATA || operation==HV_DEVICE_AUTH_BAA_DICTIONARY)) {
        auth_erase_free(body,capacity+1); return host_error(c,r,400,"invalid_auth_payload");
    }
    HvDeviceAuthRequest request={.method=r->method,.content_type=r->content_type,
        .invalid_headers=r->host_bad_headers,.has_origin=r->host_has_origin,.session=r->host_session,
        .launch_id=values.launch,.request_id=values.request,.operation=operation,
        .body=body,.body_length=used,.timeout_ms=HV_DEVICE_AUTH_TIMEOUT_DEFAULT_MS};
    HvDeviceAuthResponse response={0};
    HvDeviceAuthError error=hv_device_auth_submit(&request,&response);
    auth_erase_free(body,capacity+1);
    if (error==HV_DEVICE_AUTH_OK) error=hv_device_auth_response_revalidate(&response);
    if (error!=HV_DEVICE_AUTH_OK) {
        hv_device_auth_response_dispose(&response); return auth_service_error(c,r,error);
    }
    int result=respond(c,r,response.http_status,host_reason(response.http_status),host_json_headers,(const char *)response.body,response.body_length);
    hv_device_auth_response_dispose(&response);
    return result;
}
