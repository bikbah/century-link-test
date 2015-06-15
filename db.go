package main

import "github.com/gocql/gocql"

var DbSession *gocql.Session

func init() {
	cluster := gocql.NewCluster("127.0.0.1")
	cluster.Keyspace = "centurylink"
	cluster.Consistency = gocql.Quorum
	DbSession, _ = cluster.CreateSession()
}
