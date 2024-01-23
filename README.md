# Fail 2 Ban Traefik Plugin

This plugin will track wether a client's (based off of it's IP Address) HTTP requests to downstream are good or not. If there are too many bad requests (ie, status code 4-499 response codes), the client will be banned from making further requests for a configurable amount of time.