TRACE(1)
===

## NAME

trace - Small application for tracing a net path.

## SYNOPSIS

`trace` [-f first_ttl] [-m max_ttl] &lt;IPV4/IPV6 address&gt;

## DESCRIPTION
`trace` tracks the route packets taken from an IP network on their way to a given host.

## OPTIONS

`-f first_ttl`
  Specifies what TTL to use for the first packet. Default value is 1.

`-m max_ttl`
  Specifies maximum TTL value for packets. Default value is 30.

`IPV4/IPV6 address` IPV4/IPV6 host address.

## AUTHOR
Andrei Paplauski

## EXAMPLES

- `trace` 2a00:1450:400d:802::1000
- `trace`  -f 3 -m 20 2a00:1450:400d:802::1000
- `trace` 172.217.23.238
- `trace` -m 6 172.217.23.238


TRACE(1)
===
