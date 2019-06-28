# Trustydns Tools

This directory contains a collection of tools which may be useful when running trustydns
components. None of these tools are needed for production purposes. For those who care, the prefix
'tdt' means 'TrustyDns Tools'. At the moment, the only tools that exist are log reporting tools.

# Log Reporting Tools

As their names imply, `tdt-analyze-proxylog` and `tdt-analyze-serverlog` analyze the log output of
`trustydns-proxy` and `trustydns-server` respectively. They produce a summary of most of the
interesting statistics. The output is designed to be compact enough to send in a periodic email.

To assist with the periodic email approach, `tdt-cat-yesterday-multilogs` scans a
[multilog](http://cr.yp.to/daemontools/multilog.html) directory and outputs all log lines with
yesterday's date. In such cases, typical usage is to run the following commands just after midnight
each day:

```sh
tdt-cat-yesterday-multilogs directory-of-proxy-logs | tdt-analyze-proxylog | mail -s "trustydns-proxy Status" root
tdt-cat-yesterday-multilogs directory-of-server-logs | tdt-analyze-serverlog | mail -s "trustydns-proxy Status" root
```

