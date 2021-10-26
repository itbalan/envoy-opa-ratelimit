package envoy.authz

import input.attributes.request.http as http_request

default allow = {
	"allowed": false,
	"reason": "unauthorized resource access"
}

allow {
    action_allowed
}

#Allow Partner1 to access only GET endpoints of test service
action_allowed {
  http_request.method == "GET"
  http_request.headers.from == "partner1"
  glob.match("/test*", [], http_request.path)
}

#Allow Partner2 to access both GET/POST endpoints of test service
action_allowed {
  http_request.method == "GET"
  http_request.headers.from == "partner2"
  glob.match("/test*", [], http_request.path)	
}

action_allowed {
  http_request.method == "POST"
  http_request.headers.from == "partner2"
  glob.match("/test*", [], http_request.path)
}

#Allow all downstream systems to access both GET/POST endpoints of template service
action_allowed {
  http_request.method == "POST"
  glob.match("/template*", [], http_request.path)
}

action_allowed {
  http_request.method == "GET"
  glob.match("/template*", [], http_request.path)
}

action_allowed {
  http_request.method == "GET"
  glob.match("/actuator*", [], http_request.path)
}