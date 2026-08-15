## Sentinel local site policy. JSON logging is forced via LogAscii::use_json=T
## on the command line rather than here, so it stays visible in sensors.yml.

@load protocols/conn/mac-logging
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/dns/detect-external-names
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
