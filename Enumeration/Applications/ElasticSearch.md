# ElasticSearch

## Introduction

Elasticsearch is a distributed, open source search and analytics engine for all types of data, including textual, numerical, geospatial, structured, and unstructured.

An Elasticsearch index is a collection of documents that are related to each other. Elasticsearch stores data as JSON documents. Each document correlates a set of keys (names of fields or properties) with their corresponding values (strings, numbers, Booleans, dates, arrays of values, geolocations, or other types of data).

<https://book.hacktricks.xyz/pentesting/9200-pentesting-elasticsearch>

## Enumeration

The protocol used to access Elasticsearch is HTTP. When you access it via HTTP you will find some interesting information: http://IP:PORT/

### Important Configuration Files

The configuration files may contain credentials

- Elasticsearch configuration: /etc/elasticsearch/elasticsearch.yml
- Kibana configuration: /etc/kibana/kibana.yml
- Logstash configuration: /etc/logstash/logstash.yml
- Filebeat configuration: /etc/filebeat/filebeat.yml

####

Check if the authentication is not always enabled by default.

curl -X GET "ELASTICSEARCH-SERVER:9200/"
{
  "name" : "userver",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "lZNH15okQPWfNHp-Aks0OQ",
  "version" : {
    "number" : "7.9.3",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "c4138e51121ef06a6404866cddc601906fe5c868",
    "build_date" : "2020-10-16T10:36:16.141335Z",
    "build_snapshot" : false,
    "lucene_version" : "8.6.2",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}

If the information above is accessible, authentication most likely is disabled.

curl -X GET "ELASTICSEARCH-SERVER:9200/_xpack/security/user"

https://insinuator.net/2021/01/pentesting-the-elk-stack/