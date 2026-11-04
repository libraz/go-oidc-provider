# go-oidc-provider

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/go-oidc-provider/ci.yml?branch=main&label=CI)](https://github.com/libraz/go-oidc-provider/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/libraz/go-oidc-provider?include_prereleases&sort=semver&display_name=tag&label=release)](https://github.com/libraz/go-oidc-provider/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)
[![codecov](https://codecov.io/gh/libraz/go-oidc-provider/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/go-oidc-provider)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Docs](https://img.shields.io/badge/docs-go--oidc--provider.libraz.net-2563eb)](https://go-oidc-provider.libraz.net/ja/)

Go 向けの OpenID Connect Provider（Authorization Server）ライブラリです。`op.New(...)` が返すのは `*op.Provider` です。`Shutdown` を備えた `http.Handler` なので、`net/http` / `chi` / `gin` など任意のルータにマウントできます。フレームワークに依存せず、グローバルな状態も持ちません。対象プロファイルは FAPI 2.0 Baseline と Message Signing です。

**ドキュメント: [go-oidc-provider.libraz.net](https://go-oidc-provider.libraz.net/ja/)** — 概念・ユースケース・オプションリファレンス・運用ガイド・セキュリティ方針・適合試験スコアボードを掲載しています。本 README では、インストール手順、リポジトリの構成、採用前に把握しておくべき設計判断を扱います。

> **ステータス: `v1.5.0`**。1.0 リリース以降、公開 `op` API は [Semantic Versioning](https://semver.org/spec/v2.0.0.html) に厳密に従います。godoc に `Experimental:` マーカーを持つシンボルだけが例外で、現在の対象は Grant Management、Client ID Metadata Document、ID-JAG プロファイル（Identity Assertion JWT Authorization Grant の発行と償還）、Shared Signals で配信する RISC のセキュリティイベント型です。いずれもドラフト段階の仕様に追従しており、wire 形式がまだ変わりうるためです。一覧は [`api/experimental.txt`](api/experimental.txt) に機械生成され、`make verify` が再生成して差分を検査するため、例外の範囲がレビューを経ずに広がることはありません。移行時の注意点は [`CHANGELOG.md`](CHANGELOG.md) にまとめています。
>
> 本プロジェクトは独立して開発・保守しているもので、ベンダー製品ではありません。リリースごとに OpenID Foundation の適合試験スイートで回帰検証していますが、正式な認定は受けておらず、サポートはベストエフォートです。

## インストール

```sh
go get github.com/libraz/go-oidc-provider@v1.5.0
```

Go 1.26 以上が必要です。DB / Redis / AWS SDK のドライバを引き込むストアアダプタは、同じタグで別モジュールとして公開しています。明示的に取り込むまで、利用者の `go.sum` に余計な依存は入りません。

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.5.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.5.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.5.0
```

## クイックスタート

```go
db, err := sql.Open("mysql", dsn) // 既存のデータベース
if err != nil {
    log.Fatal(err)
}
st, err := oidcsql.New(db, oidcsql.MySQL()) // op/storeadapter/sql
if err != nil {
    log.Fatal(err)
}
// Migrate は OP のテーブルを作成または更新する。deploy job から一度だけ実行する
// （または `op-schema export` で migration ツール向けのファイルを書き出す）。
// ここで呼ぶのはサンプルを短くするため。
if err := st.Migrate(context.Background()); err != nil {
    log.Fatal(err)
}

keys, err := op.LoadKeyset("signing.pem") // PEM 形式の秘密鍵
if err != nil {
    log.Fatal(err)
}
cookieKeys, err := op.LoadSymmetricKeys("cookie.key") // 32 バイト, AES-256-GCM
if err != nil {
    log.Fatal(err)
}

handler, err := op.New(
    op.WithIssuer("https://idp.example.com"),
    op.WithStore(st),
    op.WithKeyset(keys),
    op.WithCookieKeys(cookieKeys...),
    op.WithLogger(slog.Default()), // 指定しないとリクエスト処理中の警告は破棄される
    op.WithLoginFlow(op.LoginFlow{
        Primary: op.PrimaryPassword{
            Store: users{db}, // 下の 3 メソッドを持つあなたの型
            // LegacySchemes: []op.PasswordHashScheme{op.BcryptHashScheme()}, // bcrypt ハッシュがある場合は有効にする
        },
    }),
    op.WithStaticClients(op.ConfidentialClient{ // ユーザをサインインさせるリライングパーティ
        ID:           "my-app",
        Secret:       os.Getenv("MY_APP_CLIENT_SECRET"),
        RedirectURIs: []string{"https://app.example.com/callback"},
        Scopes:       []string{"openid", "profile", "email"},
    }),
)
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", handler))
```

鍵は最初に一度だけ生成します。

```sh
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out signing.pem
openssl rand -hex 32 > cookie.key
```

`users` は既存のユーザテーブルで、OP は `store.UserPasswordStore` の 3 メソッドを通して読みます。どれも未知のユーザには `store.ErrNotFound` を返します。

```go
func (u users) FindBySubject(ctx context.Context, sub string) (*store.User, error)
func (u users) FindByUsername(ctx context.Context, login string) (*store.User, error)
func (u users) ReadPasswordHash(ctx context.Context, sub string) ([]byte, error) // PHC 形式の argon2id。bcrypt は PrimaryPassword.LegacySchemes
```

一度だけ割り当てられ再利用されない不透明な識別子（自動採番の id やメールアドレスは不可）の列がすでにあれば、テーブルに列を足す必要はありません。ID トークンと `/userinfo` のクレームも同じストアから読みます。クレームを別の場所に持つ場合だけ `op.WithUserStore` を使います。bcrypt ハッシュのテーブルには上の `LegacySchemes` の行が必要です。指定しないと、そのハッシュを持つユーザは全員ログインに失敗し、OP はこのフィールドを名指しした WARN ログを `op.WithLogger` に渡したロガーへ 1 回出力します。詳しくは [Bring your own user store](https://go-oidc-provider.libraz.net/ja/use-cases/byo-userstore) を参照してください。

`st` は OP 自身のレコード（クライアント、コード、トークン、セッション）を、利用者のテーブルと並ぶ `oidc_*` テーブルに保存します。`op.New` は構成が使うテーブルを構築時に検査し、足りないものを 1 つのエラーですべて挙げます。対象のテーブルは [`TABLES.md`](op/storeadapter/sql/schema/TABLES.md) にまとめてあります。アダプタが `db` を閉じることはなく、閉じるのは利用者側です。`go run github.com/libraz/go-oidc-provider/op/storeadapter/sql/cmd/op-schema export` を使うと、migration を golang-migrate、goose、Flyway のファイルとして書き出せます。users テーブルと migration ツールをすでに持つアプリケーションは [既存のデータベースに組み込む](https://go-oidc-provider.libraz.net/ja/getting-started/existing-db) を参照してください。

起動時、ストアにない静的クライアントは追加されますが、保存済みの内容と異なるクライアントがあると起動を拒否します。そのため、クライアントを変更したとき（redirect URI の追加、シークレットのローテーションなど）は、新しいバージョンを起動する前にデプロイジョブから `op.SyncStaticClients` で書き込みます。本番では平文の `Secret` ではなく、`go run github.com/libraz/go-oidc-provider/cmd/op-client-secret` が出力するハッシュを `SecretHash` に設定します。詳しくは [クライアントの登録パターン](https://go-oidc-provider.libraz.net/ja/use-cases/client-onboarding) を参照してください。

ログインと同意は、差し替えるまでは OP 組み込みの HTML ページで表示されます。`op.WithUI` には 3 つのモードのうち 1 つを渡します。`op.SPAUI` なら両方を自前の SPA に、`op.DriverUI` ならサーバ側で描画する自前の `interaction.Driver` に任せられます。ログイン・同意・アカウント選択のうち特定の画面のテンプレートだけを差し替えるなら `op.HTMLUI` です。どの値がどの用途に合うかは [UI の方式を選ぶ](https://go-oidc-provider.libraz.net/ja/use-cases/spa-custom-interaction#choosing-a-ui-path) の表にまとめています。OP を専用のリスナではなく既存のルータから配信する方法は [ハンドラのマウント](https://go-oidc-provider.libraz.net/ja/getting-started/mount) にあります。

`Issuer` / `Store` / `Keyset` は常に必須です。認可コード（`authorization_code`）による認可は既定で有効になっており、これを使う場合は `CookieKeys` と `LoginFlow` も必須です。`op.New` は安全でない構成のままでは起動せずにエラーを返すので、不完全な設定は構築時に弾かれます。

エンドポイントは `/oidc` の下にマウントされます（`op.WithMountPrefix` で変更できます）。discovery ドキュメントは issuer 直下の `/.well-known/openid-configuration` に置かれるので、最初はこの URL を取得してください。

セキュリティプロファイルはオプション 1 つで宣言できます。宣言したプロファイルと他の設定が食い違う場合、コンストラクタは起動を拒否します。宣言しなければ OP は `profile.OAuth21` で動き、認可コード要求のすべてに PKCE を求めます。PKCE を送れないリライングパーティには OpenID Connect Core の形が必要で、これは既定ではなく明示的に宣言します。

```go
op.WithProfile(profile.FAPI2Baseline) // PAR 必須, DPoP（または mTLS）でトークンを結び付け, ES256 のみ
op.WithProfile(profile.OIDCCore)      // confidential client の PKCE を任意にする
```

`FAPI2Baseline` は、クライアント認証アサーションの `aud` が issuer 識別子の単一の文字列である場合だけ受け付け、リフレッシュトークンもローテーションしません。リフレッシュ応答に `refresh_token` は含まれず、発行済みのトークンは有効期限まで使い続けられます。

`profile.OAuth21` は OAuth 2.1 の構えであり、FAPI 2.0 Baseline ではありません。FAPI のプロファイルは `profile.FAPI2Baseline` と `profile.FAPI2MessageSigning` です。

次に読むもの: [クイックスタート](https://go-oidc-provider.libraz.net/ja/getting-started/install)・[必須オプション](https://go-oidc-provider.libraz.net/ja/getting-started/required-options)・[ハンドラのマウント](https://go-oidc-provider.libraz.net/ja/getting-started/mount)・[セキュリティプロファイル](https://go-oidc-provider.libraz.net/ja/use-cases/security-profile)。[`examples/01-minimal`](examples/01-minimal/main.go) は同じ構成を、鍵生成・ストア接続・グレースフルシャットダウンまで含めた形で示しています。

どのページから読むか迷う場合は、[Start here](https://go-oidc-provider.libraz.net/ja/getting-started/start-here) が目的に合うページと example を案内します。

既定値は本番環境を前提にしており、https のみ・公開ネットワークのみを受け付けます。`http://127.0.0.1` は `redirect_uri` と issuer の検査から除外されているため、サンプルの大半は開発用オプションなしで動きます。`localhost`、平文 http のバックチャネル受信先、プライベートネットワークへの取得を許可するオプションは [ローカルで動かす](https://go-oidc-provider.libraz.net/ja/getting-started/required-options#running-locally) にまとめています。

## スコープ

- **`http.Handler` として埋め込みます**。フレームワークに依存せず、任意のプレフィックスにマウントできます。
- **ユーザモデルとストレージは持ち込みです**。小さな `store.*` サブストアのインターフェースを介すだけで、利用者の `users` テーブルをライブラリが直接触ることはありません。
- **対話ドライバはヘッドレスです**。ログインと同意は `op.SPAUI` で SPA に委譲することも、`op.DriverUI` で独自の `interaction.Driver` に描かせることもできます。ログイン・同意・アカウント選択のテンプレートだけを差し替えるなら `op.HTMLUI` を使います。いずれも `op.WithUI` に渡します。ログアウトの確認画面とサインアウト完了画面は既定では OP 組み込みの（ロケール対応済みの）ページで、`op.WithLogoutUI` を使えば独自テンプレートに差し替えられます。
- **観測性は監査を起点にします**。業務イベントは `audit.Emitter` を通じて集約され、`op.WithPrometheus(reg)` は厳選したカウンタ群を利用者のレジストリに登録します。`/metrics` の公開、リクエスト所要時間を測るミドルウェアの導入、ルータのラップはライブラリ側では**行いません**。これらは組み込み側の責務です。

次のものは意図的にスコープ外です。IdP ではありません（ユーザのレコードを所有せず、メール送信も持ちません）。汎用の OAuth2 フレームワークでも、UI フレームワークでもありません。詳しくは [Why this library](https://go-oidc-provider.libraz.net/ja/why) を参照してください。

## 準拠する仕様

- **コア**。OpenID Connect Core 1.0、Discovery 1.0、OAuth 2.0 (RFC 6749)、Security BCP (RFC 9700)、Authorization Server Metadata (RFC 8414)。
- **リクエストとトークンの堅牢化**。PKCE (RFC 7636)、DPoP (RFC 9449)、PAR (RFC 9126)、JAR (RFC 9101)、JARM、認可レスポンスの issuer 識別 (RFC 9207)、Rich Authorization Requests (RFC 9396)、ステップアップ認証 (RFC 9470)。
- **mTLS (RFC 8705)**。証明書にバインドしたアクセストークンと、`tls_client_auth` / `self_signed_tls_client_auth` によるクライアント認証。
- **grant**。認可コード、リフレッシュトークン、クライアントクレデンシャル、デバイス認可 (RFC 8628)、CIBA Core 1.0、Token Exchange (RFC 8693)、JWT Bearer (RFC 7523)。`op.WithCustomGrant` で組み込み側が定義した grant も追加できます。
- **トークンとクライアントのライフサイクル**。JWT アクセストークン (RFC 9068)、トークン失効 (RFC 7009)、トークンイントロスペクション (RFC 7662)、Dynamic Client Registration とその管理 API (RFC 7591 / RFC 7592)。
- **クライアント登録**。上記の Dynamic Client Registration に加え、HTTPS URL で自身を示すクライアント（MCP クライアントなど）向けに Client ID Metadata Document（experimental、明示的な opt-in）に対応しています。
- **セッションの終了**。RP-Initiated Logout 1.0、Back-Channel Logout 1.0。Front-Channel Logout は実装していません。

対象プロファイルは FAPI 2.0 Baseline と Message Signing です。RFC 別の詳細は [RFC マトリックス](https://go-oidc-provider.libraz.net/ja/compliance/rfc-matrix) にあります。各リリースは OpenID Foundation Conformance Suite に対して回帰検証しており、結果は [スコアボード](https://go-oidc-provider.libraz.net/ja/compliance/ofcs) に掲載しています。

仕様からの意図的な逸脱が 2 つあります。

- **署名アルゴリズムは OP ごとに 1 つで、既定は ES256 です**。`op.WithSigningAlgorithm(op.AlgRS256)` で OP 全体を RS256 に切り替えられますが、クライアントごとには選べません。[理由](https://go-oidc-provider.libraz.net/ja/security/design-judgments#dj-11)
- **DPoP プルーフの検証失敗は OAuth のエラー封筒で返します**。フォームポストのエンドポイントは `invalid_dpop_proof` ではなく `400 invalid_request` を返します。[理由](https://go-oidc-provider.libraz.net/ja/security/design-judgments#dj-40)

## ストレージ

[`op/store`](op/store) のサブストアインターフェースを実装すれば任意のバックエンドを利用できます。同梱するアダプタは次のとおりです。

| アダプタ | モジュール | 用途 |
|---|---|---|
| `inmem` | main module | 開発・テスト向けのリファレンス実装。 |
| `sql` | 別モジュール | SQLite / MySQL 8.0+ / PostgreSQL 14+ 向けの `database/sql` アダプタ。エンジンごとのリファレンス DDL と、リリースごとの migration ファイル（`Store.Migrations()` または `op-schema export`）を同梱。 |
| `redis` | 別モジュール | 揮発性サブストア専用。TLS と AUTH が無いと起動を拒否する。 |
| `dynamodb` | 別モジュール | サブストアごとに 1 テーブル、トランザクション対応。 |
| `composite` | main module | ホット/コールドの振り分け役。永続サブストアと揮発性サブストアを別々のバックエンドへ。 |

[`op/store/contract`](op/store/contract) は内部テストではなく、再利用できる適合ハーネスです。自作バックエンドを渡すと、godoc が規定するセマンティクスを検証し、実装していない任意拡張はスキップします。同梱アダプタもこのスイートで検証しています。

詳しくは [ストレージ構成の選び方](https://go-oidc-provider.libraz.net/ja/use-cases/storage-decision) と [ストアの自作](https://go-oidc-provider.libraz.net/ja/use-cases/byo-store) を参照してください。

## サンプル

[`examples/`](examples/README.md) に動作デモが 46 本あります。オプションや機能 1 つにつき 1 本という構成で、それぞれがドキュメントサイトの [ユースケースページ](https://go-oidc-provider.libraz.net/ja/use-cases/) に対応します。

```sh
(cd examples/01-minimal && GOWORK=off go run -tags example .)
```

ライブラリ本体を超える依存（ストアアダプタ、メトリクスクライアントなど）を引き込むサンプルは、開発用の `replace` でチェックアウトを参照する独立モジュールで、`01-minimal` と同様にリポジトリのワークスペースを無効にして実行します。それ以外は `go.mod` を持たず、チェックアウトからそのまま実行できます。内訳は [`examples/README.md`](examples/README.md) を参照してください。動作確認の対象サンプルにはそれぞれ `make example-NN` ターゲットがあり、`make example-01` は `01-minimal` を同じ方法で実行します。

[`sample/`](sample/README.md) は、オプションを 1 つずつ見せるのではなく、ひとつのアプリケーションとして組み上げたものです。アカウントを自前で持ち、同一プロセスに OP を組み込み、リライングパーティとの往復まで完結させます。ストレージは永続サブストアが MySQL、揮発性サブストアが Redis で、`op/storeadapter/composite` で束ねています。起動は `docker compose -f sample/compose.yaml up -d --build` です。デモンストレーション用であり、公開ホスティングを想定したものではありません。

## コミュニティ

- [SECURITY.md](.github/SECURITY.md) — 脆弱性報告ポリシーとサポート対象バージョン。
- [CONTRIBUTING.md](.github/CONTRIBUTING.md) — コントリビューション手順、Conventional Commits のスコープ、テスト階層の期待値。
- [CODE_OF_CONDUCT.md](.github/CODE_OF_CONDUCT.md) — Contributor Covenant 2.1 と本プロジェクトの通報窓口。

## ライセンス

Apache-2.0 です。[LICENSE](LICENSE) と [NOTICE](NOTICE) を参照してください。サードパーティ依存ライセンスは [`THIRD_PARTY.md`](THIRD_PARTY.md) で追跡し、`go.mod` から `make licenses` で再生成します。
