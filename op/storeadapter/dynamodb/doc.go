// Package oidcdynamo is the DynamoDB storage adapter for
// go-oidc-provider. It implements every substore in
// [github.com/libraz/go-oidc-provider/op/store], including
// [store.Transactional], so a deployment can run the OP — browser
// authorization-code flow included — on DynamoDB alone.
//
// Experimental: the adapter's construction and option surface has had
// no production exposure and may change in a minor release. The substore
// behaviour itself is pinned by the same op/store/contract harness the
// SQL and in-memory adapters run against, so it is not provisional.
//
// # Construction
//
// The embedder owns the AWS client, its credentials, and its region;
// the adapter only issues requests through it:
//
//	cfg, err := config.LoadDefaultConfig(ctx)
//	store, err := oidcdynamo.New(dynamodb.NewFromConfig(cfg))
//
// [Store.CreateTables] provisions the tables for development and tests.
// Production deployments are expected to drive table creation through
// their own infrastructure tooling; [Store.TableDefinitions] returns the
// same definitions so they can be translated into CloudFormation, CDK,
// or Terraform without guessing at key schemas.
//
// # Item layout
//
// Each substore owns one table. An item carries its key attributes, the
// attributes any index or condition expression needs, a TTL attribute,
// and the record itself as a JSON document under a single attribute.
// Projecting only the queried attributes keeps the mapping readable and
// keeps a record-shape change from requiring a table migration; the
// document is never the target of a condition expression, so nothing
// depends on its internal encoding.
//
// # Expiry
//
// The TTL attribute lets DynamoDB reclaim storage, but expiry is always
// enforced on read against the injected clock. DynamoDB deletes expired
// items asynchronously — AWS documents "typically within 48 hours" —
// so an expired authorization code is routinely still present in the
// table, and treating TTL as the enforcement point would leave it
// redeemable.
//
// # Consistency
//
// Every read that feeds a security decision is a strongly consistent
// GetItem. Index queries cannot be strongly consistent, so enumeration
// paths re-read each item consistently before acting on it.
package oidcdynamo
