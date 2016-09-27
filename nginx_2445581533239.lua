-- provider_key: a2303268b90e273324f1e915a7772175 --
-- https://api-2445581533239.staging.apicast.io:443 https://onews-3scale-test.herokuapp.com:443 2555417735130 onews-3scale-test.herokuapp.com --
-- -*- mode: lua; -*-
-- Generated on: 2016-09-27 19:31:21 +0000 --
-- Version:
-- Error Messages per service

-- My Own Logging Methods --
function show_table(a)
   for k,v in pairs(a) do
      local msg = ""
      msg = msg.. k
     if type(v) == "string" then
	 msg = msg.. " => " .. v
      end
      ngx.log(ngx.STDERR,msg)
   end
end

function log_message(str)
   ngx.log(ngx.STDERR, str)
end

function log(content)
   if type(content) == "table" then
      show_table(content)
   else
      log_message(content)
   end
   newline()
end

function newline()
   ngx.log(ngx.STDERR,"  ---   ")
end
-- END My Own Logging Methods --
-- Sample NGINX debug statement: ngx.log(ngx.STDERR, 'your message here') --


local custom_config = false

local _M = {
  ['services'] = {
['2555417735130'] = {
  error_auth_failed = 'Authentication failed',
  error_auth_missing = 'Authentication parameters missing',
  auth_failed_headers = 'text/plain; charset=us-ascii',
  auth_missing_headers = 'text/plain; charset=us-ascii',
  error_no_match = 'No Mapping Rule matched',
  no_match_headers = 'text/plain; charset=us-ascii',
  no_match_status = 404,
  auth_failed_status = 403,
  auth_missing_status = 403,
  secret_token = 'Shared_secret_sent_from_proxy_to_API_backend_ecf797ba4dda70a2',
  get_credentials = function(service, params)
    return (
        (params.app_id)
    ) or error_no_credentials(service)
  end,
  extract_usage = function (service, request)
    local method, url = unpack(string.split(request," "))
    local path, querystring = unpack(string.split(url, "?"))
    local usage_t =  {}
    local matched_rules = {}

    local args = get_auth_params(nil, method)

    for i,r in ipairs(service.rules) do
      check_rule({path=path, method=method, args=args}, r, usage_t, matched_rules)
    end

    -- if there was no match, usage is set to nil and it will respond a 404, this behavior can be changed
    return usage_t, table.concat(matched_rules, ", ")
  end,
  rules = {
        {
      method = 'GET',
      pattern = '/i',
      parameters = {  },
      querystring_params = function(args)
        return true
      end,
      system_name = 'hits',
      delta = 1
    },

  }
},

  }
}

-- Error Codes
function error_no_credentials(service)
  ngx.status = service.auth_missing_status
  ngx.header.content_type = service.auth_missing_headers
  ngx.print(service.error_auth_missing)
  ngx.exit(ngx.HTTP_OK)
end

function error_authorization_failed(service)
  ngx.status = service.auth_failed_status
  ngx.header.content_type = service.auth_failed_headers
  ngx.print(service.error_auth_failed)
  ngx.exit(ngx.HTTP_OK)
end

function error_no_match(service)
  ngx.status = service.no_match_status
  ngx.header.content_type = service.no_match_headers
  ngx.print(service.error_no_match)
  ngx.exit(ngx.HTTP_OK)
end
-- End Error Codes

-- Aux function to split a string

function string:split(delimiter)
  local result = { }
  local from = 1
  local delim_from, delim_to = string.find( self, delimiter, from )
  if delim_from == nil then return {self} end
  while delim_from do
    table.insert( result, string.sub( self, from , delim_from-1 ) )
    from = delim_to + 1
    delim_from, delim_to = string.find( self, delimiter, from )
  end
  table.insert( result, string.sub( self, from ) )
  return result
end

function first_values(a)
  r = {}
  for k,v in pairs(a) do
    if type(v) == "table" then
      r[k] = v[1]
    else
      r[k] = v
    end
  end
  return r
end

function set_or_inc(t, name, delta)
  return (t[name] or 0) + delta
end

function build_querystring_formatter(fmt)
  return function (query)
    local function kvmap(f, t)
      local res = {}
      for k, v in pairs(t) do
        table.insert(res, f(k, v))
      end
      return res
    end

    return table.concat(kvmap(function(k,v) return string.format(fmt, k, v) end, query or {}), "&")
  end
end

local build_querystring = build_querystring_formatter("usage[%s]=%s")
local build_query = build_querystring_formatter("%s=%s")

function regexpify(path)
  return path:gsub('?.*', ''):gsub("{.-}", '([\\w_.-]+)'):gsub("%.", "\\.")
end

function check_rule(req, rule, usage_t, matched_rules)
  local param = {}
  local p = regexpify(rule.pattern)
  local m = ngx.re.match(req.path,
                         string.format("^%s",p))
  if m and req.method == rule.method then
    local args = req.args
    if rule.querystring_params(args) then -- may return an empty table
                                          -- when no querystringparams
                                          -- in the rule. it's fine
      for i,p in ipairs(rule.parameters) do
        param[p] = m[i]
      end

    table.insert(matched_rules, rule.pattern)
    usage_t[rule.system_name] = set_or_inc(usage_t, rule.system_name, rule.delta)
    end
  end
end

--[[
  Authorization logic
]]--

function get_auth_params(where, method)
  local params = {}
  if where == "headers" then
    params = ngx.req.get_headers()
  elseif method == "GET" then
    params = ngx.req.get_uri_args()
  else
    ngx.req.read_body()
    params = ngx.req.get_post_args()
  end
  return first_values(params)
end

function get_debug_value()
  local h = ngx.req.get_headers()
  if h["X-3scale-debug"] == 'a2303268b90e273324f1e915a7772175' then
    return true
  else
    return false
  end
end

function _M.authorize(auth_strat, params, service)
  if auth_strat == 'oauth' then
    oauth(params, service)
  else
    authrep(params, service)
  end
end

function oauth(params, service)
  ngx.var.cached_key = ngx.var.cached_key .. ":" .. ngx.var.usage
  local access_tokens = ngx.shared.api_keys
  local is_known = access_tokens:get(ngx.var.cached_key)

  if is_known ~= 200 then
    local res = ngx.location.capture("/threescale_oauth_authrep", { share_all_vars = true })

    -- IN HERE YOU DEFINE THE ERROR IF CREDENTIALS ARE PASSED, BUT THEY ARE NOT VALID
    if res.status ~= 200   then
      access_tokens:delete(ngx.var.cached_key)
      ngx.status = res.status
      ngx.header.content_type = "application/json"
      ngx.var.cached_key = nil
      error_authorization_failed(service)
    else
      access_tokens:set(ngx.var.cached_key,200)
    end

    ngx.var.cached_key = nil
  end
end

function authrep(params, service)
  ngx.var.cached_key = ngx.var.cached_key .. ":" .. ngx.var.usage
  local api_keys = ngx.shared.api_keys
  local is_known = api_keys:get(ngx.var.cached_key)

  if is_known ~= 200 then
    local res = ngx.location.capture("/threescale_authrep", { share_all_vars = true })
    
    -- MY
  	log('--res:');
  	log(res);
  	-- END MY

    -- IN HERE YOU DEFINE THE ERROR IF CREDENTIALS ARE PASSED, BUT THEY ARE NOT VALID
    if res.status ~= 200 then
      -- remove the key, if it's not 200 let's go the slow route, to 3scale's backend
      api_keys:delete(ngx.var.cached_key)
      ngx.status = res.status
      ngx.header.content_type = "application/json"
      ngx.var.cached_key = nil
      error_authorization_failed(service)
    else
      api_keys:set(ngx.var.cached_key,200)
    end
    ngx.var.cached_key = nil
  end
end

function _M.access()
  local params = {}
  local host = ngx.req.get_headers()["Host"]
  local auth_strat = ""
  local service = {}
  local usage = {}
  local matched_patterns = ''

  if ngx.status == 403  then
    ngx.say("Throttling due to too many requests")
    ngx.exit(403)
  end

  if ngx.var.service_id == '2555417735130' then
  local parameters = get_auth_params("not_headers", string.split(ngx.var.request, " ")[1] )
  service = _M.services['2555417735130'] --
  ngx.var.secret_token = service.secret_token
  params.app_id = parameters["app_id"]
  params.app_key = parameters["app_key"]  -- or ""  -- Uncoment the first part if you want to allow not passing app_key
  service.get_credentials(service, params)
  ngx.var.cached_key = "2555417735130" .. ":" .. params.app_id ..":".. params.app_key
  auth_strat = "2"
  ngx.var.service_id = "2555417735130"
  ngx.var.proxy_pass = "https://backend_2555417735130"
  usage, matched_patterns = service:extract_usage(ngx.var.request)
end


  ngx.var.credentials = build_query(params)
  ngx.var.usage = build_querystring(usage)

  -- WHAT TO DO IF NO USAGE CAN BE DERIVED FROM THE REQUEST.
  if ngx.var.usage == '' then
    ngx.header["X-3scale-matched-rules"] = ''
    error_no_match(service)
  end

  if get_debug_value() then
    ngx.header["X-3scale-matched-rules"] = matched_patterns
    ngx.header["X-3scale-credentials"]   = ngx.var.credentials
    ngx.header["X-3scale-usage"]         = ngx.var.usage
    ngx.header["X-3scale-hostname"]      = ngx.var.hostname
  end

  _M.authorize(auth_strat, params, service)
end


function _M.post_action_content()
  local method, path, headers = ngx.req.get_method(), ngx.var.request_uri, ngx.req.get_headers()

  local req = cjson.encode{method=method, path=path, headers=headers}
  local resp = cjson.encode{ body = ngx.var.resp_body, headers = cjson.decode(ngx.var.resp_headers)}

  local cached_key = ngx.var.cached_key
  if cached_key ~= nil and cached_key ~= "null" then
    local status_code = ngx.var.status
    local res1 = ngx.location.capture("/threescale_authrep?code=".. status_code .. "&req=" .. ngx.escape_uri(req) .. "&resp=" .. ngx.escape_uri(resp), { share_all_vars = true })
    if res1.status ~= 200 then
      local api_keys = ngx.shared.api_keys
      api_keys:delete(cached_key)
    end
  end

  ngx.exit(ngx.HTTP_OK)
end

if custom_config then
  local ok, c = pcall(function() return require(custom_config) end)
  if ok and type(c) == 'table' and type(c.setup) == 'function' then
    c.setup(_M)
  end
end


return _M

-- END OF SCRIPT
