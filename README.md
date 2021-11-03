# Apigee-Remote-Service-File

A simple file-based service to stand in for the remote-service proxy
on Apigee. All configuration is done locally in a YAML file and service
responds to Envoy Adapter as if it were the Apigee proxy.

## Usage

### Build

```sh
go build .
```

### Make and edit config file

```sh
cp config-example.yaml config.yaml
```

### Run service

```sh
./apigee-remote-service-file -h
```

### Connect to Envoy Adapter

The service will emit a simple config that can be consumed by 
Envoy Adapter to connect. Hint: Use `-addr` flag to use a 
consistent port in order to avoid having to change your EA config
on each start.

## Notes

* No security checks on requests.
* Quotas are maintained starting from zero.
