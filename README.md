# rfDNS for compute

This is a compute service that returns a reverse forward DNS lookup result over HTTP.
The results are cached into the KV store based on the TTL on the result. It is recommended to not mix and match resolvers, based on the differing TTLs.

To run locally, you must have the fastly cli installed with the appropriate Fastly Token credentials provided:
```
fastly compute init
fastly compute build
fastly compute serve
```

The endpoint exposed is:
```
{fqdn}/verify?ip=<ip-you-want-to-lookup>
```

Example request:
```
$ curl -s "http://127.0.0.1:7676/verify?ip=108.174.2.216" | jq                                                                                    ~  
{
  "result": "ok",
  "answer": "108-174-2-216.fwd.linkedin.com",
  "duration_ms": 0.165362
}
```

To use cloudflare:
```
curl -s "http://127.0.0.1:7676/verify?ip=108.174.8.21&resolver=google" | jq                                                                                    ~  
{
  "result": "ok",
  "answer": "108-174-2-216.fwd.linkedin.com",
  "duration_ms": 0.165362
}
```

To publish to a live compute service:
```
fastly compute publish
```