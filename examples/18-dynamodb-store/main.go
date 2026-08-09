//go:build example

// Example 18-dynamodb-store wires the DynamoDB storage adapter
// (op/storeadapter/dynamodb) into a runnable Provider. Every substore
// — durable (clients, codes, refresh tokens, grants, access tokens,
// users, IATs, RATs) and volatile (sessions, interactions, consumed
// JTIs) — lives in DynamoDB, one table per substore.
//
// The point of the example is that the browser Authorization Code
// flow runs on DynamoDB alone. That flow requires store.Transactional
// (grant creation, PAR consumption, and code persistence commit as one
// operation), and DynamoDB has no interactive transaction: the adapter
// buffers the writes a transaction makes and commits them as a single
// TransactWriteItems. Nothing in this file has to know that, which is
// the property worth demonstrating.
//
// It complements 07-mysql-store, which is the same demo on a
// relational engine, and 09-redis-volatile, which splits volatile
// substores onto a second backend.
//
// # What you can verify
//
// Two listeners come up in the same Go process:
//
//   - :8080 — the OP, with issuer http://127.0.0.1:8080, one seeded
//     password user (demo / demo), and one statically-registered
//     public client whose redirect URI points at the RP.
//   - :9090 — the RP, built from examples/internal/rpkit. It exposes
//     /, /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — RP landing page.
//  2. Click "Log in via the OP" — the browser is redirected to the OP.
//  3. Sign in as username "demo" / password "demo".
//  4. Approve the consent prompt.
//  5. The browser ends up at http://127.0.0.1:9090/me with the
//     verified ID Token claims rendered as JSON.
//
// # Configuration
//
// Two wiring modes, chosen by whether an endpoint override is present:
//
//	DYNAMODB_ENDPOINT       when set, the client targets this endpoint
//	                        with placeholder static credentials — the
//	                        shape used against a local emulator. When
//	                        unset, the client is built from the ambient
//	                        AWS configuration (config.LoadDefaultConfig),
//	                        which is the production shape: real region,
//	                        real credential chain, no endpoint override.
//	AWS_REGION              default us-east-1 in endpoint-override mode
//	DYNAMODB_TABLE_PREFIX   default oidc_ (the adapter's own default)
//	DYNAMODB_CREATE_TABLES  "1" or "0"; defaults to on in
//	                        endpoint-override mode and off otherwise
//
// # Running
//
// The example ships a docker-compose stack that runs both the
// emulator and the OP+RP binary on a private docker network. The
// emulator is not exposed to the host; only the OP container publishes
// 8080 and 9090 so the browser can drive the flow:
//
//	docker compose -f examples/18-dynamodb-store/compose.yaml up -d --build
//	open http://127.0.0.1:9090/
//	# sign in as demo / demo, approve consent
//	docker compose -f examples/18-dynamodb-store/compose.yaml down -v
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Table provisioning: CreateTables is a development shortcut.
//     Production drives table creation from its own infrastructure
//     tooling; Store.TableDefinitions() returns the same key schemas,
//     indexes, and TTL attributes so they can be translated into
//     CloudFormation / CDK / Terraform without guessing.
//   - Capacity and billing mode: CreateTables provisions on-demand
//     tables. Deployments with a predictable load profile choose per
//     substore — the interaction table and the client table have very
//     different write shapes.
//   - Credentials: the endpoint-override mode below uses placeholder
//     static credentials because an emulator validates the signature's
//     shape but not the key. Never carry that branch into production;
//     the default path resolves the real credential chain.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded;
//     production embedders enrol users through their own management
//     plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "demo-rp"
	redirectURI = rpBase + "/callback"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"

	// dynamoReadyTimeout bounds the wait for the emulator to accept
	// requests. The compose stack starts both containers at once and
	// the emulator's JVM needs a moment, so the example retries rather
	// than depending on a healthcheck the image cannot serve.
	dynamoReadyTimeout = 30 * time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	keys := devkeys.MustEphemeral("dynamodb-store-1")

	client, label, override, err := dynamoClient(ctx)
	if err != nil {
		return err
	}

	readyCtx, cancel := context.WithTimeout(ctx, dynamoReadyTimeout)
	defer cancel()
	if err := waitForDynamo(readyCtx, client); err != nil {
		return err
	}

	opts := []oidcdynamo.Option{}
	if prefix := os.Getenv("DYNAMODB_TABLE_PREFIX"); prefix != "" {
		opts = append(opts, oidcdynamo.WithTablePrefix(prefix))
	}
	storage, err := oidcdynamo.New(client, opts...)
	if err != nil {
		return fmt.Errorf("oidcdynamo.New: %w", err)
	}

	if shouldCreateTables(override) {
		// CreateTables is idempotent: a table that already exists is
		// left alone, so a restart against a persistent emulator (or a
		// re-run against a dev account) is not an error.
		if err := storage.CreateTables(ctx); err != nil {
			return fmt.Errorf("create tables: %w", err)
		}
	}
	log.Printf("dynamodb store ready (%s, %d tables)", label, len(storage.TableDefinitions()))

	if err := seedUser(ctx, storage); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: storage.UserPasswords()},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile", "email"},
		}),
	)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)

	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	rpCtx, rpCancel := context.WithTimeout(ctx, 5*time.Second)
	defer rpCancel()
	if err := serve.WaitForIssuer(rpCtx, issuer); err != nil {
		return err
	}

	rp, err := rpkit.New(ctx, rpkit.Options{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Scopes:      []string{"openid", "profile", "email"},
	})
	if err != nil {
		return fmt.Errorf("rpkit.New: %w", err)
	}

	rpMux := http.NewServeMux()
	rpMux.Handle("/", rp.Handler())

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

// dynamoClient builds the AWS client and reports the label to print at
// startup plus whether an endpoint override was in play.
//
// The two branches are the whole configuration story. With
// DYNAMODB_ENDPOINT set the client targets that endpoint with
// placeholder static credentials, which is what an emulator accepts:
// it verifies that a request is signed, not which key signed it.
// Without it, the ambient AWS configuration supplies the region,
// the credential chain, and the real service endpoint — the adapter
// itself never reads an environment variable.
func dynamoClient(ctx context.Context) (client *awsdynamodb.Client, label string, override bool, err error) {
	endpoint := os.Getenv("DYNAMODB_ENDPOINT")
	if endpoint == "" {
		cfg, cfgErr := awsconfig.LoadDefaultConfig(ctx)
		if cfgErr != nil {
			return nil, "", false, fmt.Errorf("load aws config: %w", cfgErr)
		}
		return awsdynamodb.NewFromConfig(cfg), "aws region " + cfg.Region, false, nil
	}

	safe, err := redactedEndpoint(endpoint)
	if err != nil {
		return nil, "", false, err
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	return awsdynamodb.New(awsdynamodb.Options{
		Region:       region,
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
	}), safe, true, nil
}

// redactedEndpoint returns scheme://host for raw, dropping userinfo,
// path, and query. The endpoint is operator-supplied configuration and
// a URL's userinfo section can carry a credential, so the startup
// banner must not echo it back verbatim. An input without a host is
// rejected rather than logged, and the error text quotes nothing from
// the input.
func redactedEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return "", errors.New("DYNAMODB_ENDPOINT is not a valid scheme://host URL")
	}
	return u.Scheme + "://" + u.Host, nil
}

// shouldCreateTables reports whether the demo provisions its own
// tables. DYNAMODB_CREATE_TABLES overrides the default, which is on
// only when an endpoint override is in play: against real AWS, table
// creation belongs to the infrastructure tooling that owns capacity
// and backup policy, not to the process serving traffic.
func shouldCreateTables(override bool) bool {
	switch os.Getenv("DYNAMODB_CREATE_TABLES") {
	case "1":
		return true
	case "0":
		return false
	default:
		return override
	}
}

// waitForDynamo polls ListTables until the service answers or ctx is
// cancelled. The compose stack brings the emulator and the OP up
// together and the emulator image ships no healthcheck-capable tooling,
// so readiness is established by the client instead.
func waitForDynamo(ctx context.Context, client *awsdynamodb.Client) error {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := client.ListTables(ctx, &awsdynamodb.ListTablesInput{}); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("waitForDynamo: timeout waiting for DynamoDB to accept requests")
		case <-tick.C:
		}
	}
}

func seedUser(ctx context.Context, storage *oidcdynamo.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	user := &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}
	return storage.PutUserWithPassword(ctx, user, demoUsername, hash)
}
