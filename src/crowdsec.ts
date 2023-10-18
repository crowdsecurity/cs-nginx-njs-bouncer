/// <reference path="./types/ngx_http_js_module.d.ts" />

export default { lapiPoller, getDecisionForRequest, serveBanTemplate, serveCaptchaTemplate, serveCaptchaSubmissionHandler} 

var fs = require("fs")

const querystring = require('querystring');

// @ts-ignore
const config:Config = crowdsec_config

// @ts-ignore
const ip2CountryCache:NgxSharedDict<string> = ngx.shared.ip_to_country_cache

// @ts-ignore
const ip2asCache:NgxSharedDict<string> = ngx.shared.ip_to_as_cache

function getASForIP(ip: string): string {
    const cacheResult = ip2asCache.get(ip)
    if ( typeof cacheResult == "string" && cacheResult != "" ) {
        return cacheResult
    }

    // @ts-ignore
    const reader = new GeoIP2(config.as_remediations.ip_to_as_mmdb_path);
    const result = reader.getRecord(ip).autonomous_system_number
    ip2asCache.set(ip, result.toString().toLowerCase())
    return result
}

function getCountryForIP(ip: string): string {
    const cacheResult =  ip2CountryCache.get(ip)
    if ( typeof cacheResult == "string" && cacheResult != "" ) {
        return cacheResult
    }

    // @ts-ignore
    const reader = new GeoIP2(config.country_remediations.ip_to_country_mmdb_path);
    const result = reader.getRecord(ip).country.iso_code
    ip2CountryCache.set(ip, result.toLowerCase())
    return result
}

function prepareRequest(config: Config): Request {

    let lapiURL = config.crowdsec_config.lapi_url
    if (!config.crowdsec_config.lapi_url.endsWith("/")) {
        lapiURL += "/"
    }

    const startup = "true" ? ngx.shared.crowdsec_decision_store.size() == 0 : "false"
    lapiURL += "v1/decisions/stream?startup=" + startup

    if (config.crowdsec_config.exclude_scenarios_containing.length) {
        lapiURL += "&scenarios_not_containing=" + config.crowdsec_config.exclude_scenarios_containing.join(",")
    }

    if (config.crowdsec_config.include_scenarios_containing.length) {
        lapiURL += "&scenarios_containing=" + config.crowdsec_config.include_scenarios_containing.join(",")
    }

    if (config.crowdsec_config.only_include_decisions_from.length) {
        lapiURL += "&origins=" + config.crowdsec_config.only_include_decisions_from.join(",")
    }

    lapiURL += "&scopes=ip,range"
    if (config.as_remediations.enabled) {
        lapiURL += ",as"
    }
    if(config.country_remediations.enabled){
        lapiURL += ",country"
    }
    return new Request(lapiURL, { headers: { "x-api-key": config.crowdsec_config.lapi_key } })
}

async function lapiPoller(): Promise<void> {
    if (ngx.worker_id != 0) {
        return;
    }

    const lapiReq = prepareRequest(config)
    const resp = await ngx.fetch(lapiReq)
    const respJSON = await resp.json()
    ngx.shared.crowdsec_decision_store.add("IP_RANGES", "{}")

    // @ts-ignore
    const currentIPRanges:any = JSON.parse(ngx.shared.crowdsec_decision_store.get("IP_RANGES"))
    let ipRangesChanged = false

    if ("deleted" in respJSON && Array.isArray(respJSON["deleted"])) {
        respJSON["deleted"].forEach((decision: any) => {
            decision = normalizeDecision(decision)
            if(decision.scope == "range"){
                delete currentIPRanges[decision.value]
                ipRangesChanged = true
            } else {
                ngx.shared.crowdsec_decision_store.delete(decision.value)
            }
        })
    }

    if ("new" in respJSON && Array.isArray(respJSON["new"])) {
        respJSON["new"].forEach((decision: any) => {
            decision = normalizeDecision(decision)
            if(decision.scope == "range"){
                currentIPRanges[decision.value] = decision.type
                ipRangesChanged = true
            } else {
                ngx.shared.crowdsec_decision_store.set(decision.value, decision.type.toString())
            }
        })
    }
    if(ipRangesChanged){
        ngx.shared.crowdsec_decision_store.set("IP_RANGES", JSON.stringify(currentIPRanges))
    }
}

function normalizeDecision(decision: any): any {
    decision.value = decision.value.toLowerCase()
    decision.type = decision.type.toLowerCase()
    decision.scope = decision.scope.toLowerCase()
    decision.origin = decision.origin.toLowerCase() 
    return decision
}

function serveBanTemplate(r: NginxHTTPRequest): void {
    r.headersOut["Content-Type"] = "text/html"
    if ("ban_template_path" in r) {
        return fs.readFileSync(r.ban_template_path)
    }
    return fs.readFileSync(config.ban.template_path)
}

function isCaptchaSubmission(r: NginxHTTPRequest): boolean {
    return "captcha_token" in r.args
}

async function captchaSubmissionIsCorrect(r: NginxHTTPRequest): Promise<boolean>{
    let siteVerifyURL:string

    if(config.captcha.provider == "google_recaptcha_v2"){
        siteVerifyURL = "https://www.google.com/recaptcha/api/siteverify"
    } else if(config.captcha.provider == "hcaptcha"){
        siteVerifyURL = "https://hcaptcha.com/siteverify"
    } else {
        siteVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    }

    const captchaToken = r.args["captcha_token"]
    const body = querystring.stringify({
        secret:  config.captcha.secret_key,
        response: captchaToken,
        remoteip: r.remoteAddress
    });
    const result =  await ngx.fetch(siteVerifyURL, {
        body: body,
        method: 'POST',
        headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
        }
    });
    
    const outcome =  await result.json();
    return outcome["success"] === true;
}


async function serveCaptchaSubmissionHandler(r: NginxHTTPRequest): Promise<void> {
    if(await captchaSubmissionIsCorrect(r) == true){
        // @ts-ignore
        const cookie = jwt.encode({"exp": Date.now()/1000 + 1800}, config.captcha.secret_key + r.remoteAddress)
        r.headersOut["Set-Cookie"] = ["crowdsec_captcha=" + cookie + "; Path=/; HttpOnly; SameSite=Strict"]
        r.return(200, "OK")
    } else{
        r.return(401, "Unauthorized")
    }
}


function serveCaptchaTemplate(r: NginxHTTPRequest): string|Buffer {
    r.headersOut["Content-Type"] = "text/html"
    if ("captcha_template_path" in r) {
        return fs.readFileSync(r.captcha_template_path)
    }
    let captchaTemplate:string = fs.readFileSync(config.captcha.template_path).toString()
    captchaTemplate = captchaTemplate.replaceAll("{{captcha_site_key}}", config.captcha.site_key)
    captchaTemplate = captchaTemplate.replaceAll("{{captcha_frontend_js}}", jsForCaptchaProvider(config.captcha.provider))
    return captchaTemplate.replaceAll("{{captcha_frontend_css_class}}", cssClassForCaptchaProvider(config.captcha.provider))
}


const jsForCaptchaProvider = (provider:string):string => {
    return {
        "turnstile": "https://challenges.cloudflare.com/turnstile/v0/api.js",
        "google_recaptcha_v2":  "https://www.google.com/recaptcha/api.js",
        "hcaptcha": "https://hcaptcha.com/1/api.js"
    }[provider]
}

const cssClassForCaptchaProvider = (provider:string):string => {
    return {
        "turnstile": "cf-turnstile",
        "google_recaptcha_v2":  "g-recaptcha",
        "hcaptcha": "h-captcha"
    }[provider]
}


function alignDecisionWithConfig(decision:string, r: NginxHTTPRequest): string {
    const ret = _alignDecisionWithConfig(decision, r)
    if(ret  == "captcha" && isCaptchaSubmission(r)){
        return "captcha_submission"
    }
    return ret
}

function _alignDecisionWithConfig(decision:string, r: NginxHTTPRequest): string {
    if (decision == "ban") {
        if ("disable_ban" in r) {
            if (r.disable_ban == "true" || r.disable_ban == "1") {
                return "pass"
            } else {
                return "ban"
            }
        } else if (!config.ban.enabled){
            return "pass"
        }
        return "ban"
    } else if (decision == "captcha") {
        if ("disable_captcha" in r) {
            if (r.disable_captcha == "true" || r.disable_captcha == "1") {
                return "pass"
            } else {
                return  hasValidCaptchaCookie(r) ? "pass" : "captcha"
            }
        } else if (!config.captcha.enabled){
            return "pass"
        }

        return hasValidCaptchaCookie(r) ? "pass" : "captcha"
    } 
    return config.fallback_decision
}

function hasValidCaptchaCookie(r: NginxHTTPRequest): boolean {
    // @ts-ignore
    const captchaCookie = cookie.parse(r.headersIn.Cookie || "")

    if( "crowdsec_captcha" in captchaCookie ) {
        try{
        // @ts-ignore
        jwt.decode(captchaCookie["crowdsec_captcha"],
            config.captcha.secret_key + r.remoteAddress,
            false,
            )
        } catch (e) {
            return false
        }
        return true
    }
    return false
}

function getDecisionForRequest(r: NginxHTTPRequest): string {
    // TODO: handle cases where there could be multiple decisions of diffetent type for the same IP
    // For that we'll need to map ip to an stringified array of decisions

    const ipDecision = ngx.shared.crowdsec_decision_store.get(r.remoteAddress)
    if (typeof(ipDecision)=="string" && ipDecision != "") {
        return alignDecisionWithConfig(ipDecision, r)
    }
    if(config.country_remediations.enabled){
        const country = getCountryForIP(r.remoteAddress)
        const countryDecision =  ngx.shared.crowdsec_decision_store.get(country)
        if(typeof(countryDecision)=="string" && countryDecision != ""){
            return alignDecisionWithConfig(countryDecision, r)
        }
    }

    if(config.as_remediations.enabled){
        const as = getASForIP(r.remoteAddress)
        const asDecision =  ngx.shared.crowdsec_decision_store.get(as)
        if(typeof(asDecision)=="string" && asDecision != ""){
            return alignDecisionWithConfig(asDecision, r)
        }
    }
    // @ts-ignore
    const actionByIPRange:Object = JSON.parse(ngx.shared.crowdsec_decision_store.get("IP_RANGES"));

    // @ts-ignore
    const clientIPAddr = ipaddr.parse(r.remoteAddress);

    const entries = Object.entries(actionByIPRange);
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const range = entry[0];
      const action = entry[1];
      // @ts-ignore
      if (clientIPAddr.match(ipaddr.parseCIDR(range))) {
        return alignDecisionWithConfig(action, r)
      }
    }
    return "pass"
}

export interface Config {
    crowdsec_config: CrowdsecConfig;
    ban: Ban;
    captcha: Captcha;
    as_remediations: ASRemediations;
    country_remediations: CountryRemediations;
    fallback_decision: string;
}

export interface Ban {
    enabled: boolean;
    template_path: string;
}

export interface Captcha {
    enabled: boolean;
    template_path: string;
    site_key: string;
    secret_key: string;
    provider: string;
}

export interface CrowdsecConfig {
    lapi_key: string;
    lapi_url: string;
    include_scenarios_containing: any[];
    exclude_scenarios_containing: any[];
    only_include_decisions_from: any[];
}

export interface CountryRemediations {
    enabled: boolean;
    ip_to_country_mmdb_path: string;
}

export interface ASRemediations {
    enabled: boolean;
    ip_to_as_mmdb_path: string;
}
