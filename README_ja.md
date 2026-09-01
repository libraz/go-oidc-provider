# go-oidc-provider

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/go-oidc-provider/ci.yml?branch=main&label=CI)](https://github.com/libraz/go-oidc-provider/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/libraz/go-oidc-provider?include_prereleases&sort=semver&display_name=tag&label=release)](https://github.com/libraz/go-oidc-provider/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)
[![codecov](https://codecov.io/gh/libraz/go-oidc-provider/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/go-oidc-provider)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Docs](https://img.shields.io/badge/docs-go--oidc--provider.libraz.net-2563eb)](https://go-oidc-provider.libraz.net/ja/)
[![Go Report Card](https://goreportcard.com/badge/github.com/libraz/go-oidc-provider)](https://goreportcard.com/report/github.com/libraz/go-oidc-provider)

Go 向けの OpenID Connect Provider（Authorization Server）ライブラリです。`op.New(...)` が返すのは標準の `http.Handler` なので、`net/http` / `chi` / `gin` など任意のルータにマウントできます。フレームワークに依存せず、グローバルな状態も持ちません。対象プロファイルは FAPI 2.0 Baseline と Message Signing です。

**ドキュメント: [go-oidc-provider.libraz.net](https://go-oidc-provider.libraz.net/ja/)** — 概念・ユースケース・オプションリファレンス・運用ガイド・セキュリティ方針・適合試験スコアボードを掲載しています。本 README では、インストール手順、リポジトリの構成、採用前に把握しておくべき設計判断を扱います。

> **ステータス: `v1.2.0`**。1.0 リリース以降、公開 `op` API は [Semantic Versioning](https://semver.org/spec/v2.0.0.html) に厳密に従います。godoc に `Experimental:` マーカーを持つシンボルだけが例外で、対象は認証ステップのシーム、interaction の UI 型、Grant Management の 3 つです。一覧は [`api/experimental.txt`](api/experimental.txt) に機械生成され、`make verify` が再生成して差分を検査するため、例外の範囲がレビューを経ずに広がることはありません。移行時の注意点は [`CHANGELOG.md`](CHANGELOG.md) にまとめています。
>
> 本プロジェクトは独立して開発・保守しているもので、ベンダー製品ではありません。リリースごとに OpenID Foundation の適合試験スイートで回帰検証していますが、正式な認定は受けておらず、サポートはベストエフォートです。

## インストール

```sh
go get github.com/libraz/go-oidc-provider@v1.2.0
```

Go 1.25 以上が必要です。DB / Redis / AWS SDK のドライバを引き込むストアアダプタは、同じタグで別モジュールとして公開しています。明示的に取り込むまで、利用者の `go.sum` に余計な依存は入りません。

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.2.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.2.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.2.0
```

## クイックスタート

```go
handler, err := op.New(
    op.WithIssuer("https://idp.example.com"),
    op.WithStore(st),
    op.WithKeyset(op.Keyset{{KeyID: "k1", Signer: priv}}),
    op.WithCookieKeys(cookieKey), // 32 バイト, AES-256-GCM
    op.WithLoginFlow(op.LoginFlow{
        Primary: op.PrimaryPassword{Store: st.UserPasswords()},
    }),
)
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", handler))
```

`Issuer` / `Store` / `Keyset` は常に必須です。認可コード（`authorization_code`）による認可は既定で有効になっており、これを使う場合は `CookieKeys` も必須です。`op.New` は安全でない構成のままでは起動せずにエラーを返すので、不完全な設定は構築時に弾かれます。

セキュリティプロファイルはオプション 1 つで宣言できます。宣言したプロファイルと他の設定が食い違う場合、コンストラクタは起動を拒否します。

```go
op.WithProfile(profile.Baseline)      // OAuth 2.1: code 要求すべてに PKCE 必須
op.WithProfile(profile.FAPI2Baseline) // PAR + JAR + DPoP, ES256, alg ロック
```

次に読むもの: [クイックスタート](https://go-oidc-provider.libraz.net/ja/getting-started/install)・[必須オプション](https://go-oidc-provider.libraz.net/ja/getting-started/required-options)・[ハンドラのマウント](https://go-oidc-provider.libraz.net/ja/getting-started/mount)・[セキュリティプロファイル](https://go-oidc-provider.libraz.net/ja/use-cases/security-profile)。[`examples/01-minimal`](examples/01-minimal/main.go) は同じ構成を、鍵生成・ストア接続・グレースフルシャットダウンまで含めた形で示しています。

既定値は本番環境を前提にしており、https のみ・公開ネットワークのみを受け付けます。`http://127.0.0.1` はこの 2 つの検査から除外されているため、サンプルの大半は開発用オプションなしで動きます。IP リテラルでは足りないケースは 2 つあり、文字列ホストの `localhost` を使う場合と、平文 http の `backchannel_logout_uri` を登録する場合です。いずれも [`redirect_uri`](https://go-oidc-provider.libraz.net/ja/concepts/redirect-uri) と [Issuer](https://go-oidc-provider.libraz.net/ja/concepts/issuer) で説明しています。

## スコープ

- **`http.Handler` として埋め込みます**。フレームワークに依存せず、任意のプレフィックスにマウントできます。
- **ユーザモデルとストレージは持ち込みです**。小さな `store.*` サブストアのインターフェースを介すだけで、利用者の `users` テーブルをライブラリが直接触ることはありません。
- **対話ドライバはヘッドレスです**。`op.WithSPAUI` でログイン・同意・ログアウトを SPA に委譲でき、`op.WithConsentUI` で独自テンプレートに差し替えることもできます。
- **観測性は監査を起点にします**。業務イベントは `audit.Emitter` を通じて集約され、`op.WithPrometheus(reg)` は厳選したカウンタ群を利用者のレジストリに登録します。`/metrics` の公開、リクエスト所要時間を測るミドルウェアの導入、ルータのラップはライブラリ側では**行いません**。これらは組み込み側の責務です。

次のものは意図的にスコープ外です。IdP ではありません（ユーザテーブル・パスワードハッシュ・メール送信を持ちません）。汎用の OAuth2 フレームワークでも、UI フレームワークでもありません。詳しくは [Why this library](https://go-oidc-provider.libraz.net/ja/why) を参照してください。

## 準拠する仕様

- **コア**。OpenID Connect Core 1.0、Discovery 1.0、OAuth 2.0 (RFC 6749)、Security BCP (RFC 9700)、Authorization Server Metadata (RFC 8414)。
- **リクエストとトークンの堅牢化**。PKCE (RFC 7636)、DPoP (RFC 9449)、PAR (RFC 9126)、JAR (RFC 9101)、JARM、mTLS (RFC 8705)、認可レスポンスの issuer 識別 (RFC 9207)、Rich Authorization Requests (RFC 9396)、ステップアップ認証 (RFC 9470)。
- **grant**。認可コード、リフレッシュトークン、クライアントクレデンシャル、デバイス認可 (RFC 8628)、CIBA Core 1.0、Token Exchange (RFC 8693)。`op.WithCustomGrant` で組み込み側が定義した grant も追加できます。
- **トークンとクライアントのライフサイクル**。JWT アクセストークン (RFC 9068)、トークン失効 (RFC 7009)、トークンイントロスペクション (RFC 7662)、Dynamic Client Registration とその管理 API (RFC 7591 / RFC 7592)。
- **セッションの終了**。RP-Initiated Logout 1.0、Back-Channel Logout 1.0。Front-Channel Logout は実装していません。

対象プロファイルは FAPI 2.0 Baseline と Message Signing です。RFC 別の詳細は [RFC マトリックス](https://go-oidc-provider.libraz.net/ja/compliance/rfc-matrix) にあります。各リリースは OpenID Foundation Conformance Suite に対して回帰検証しており、結果は [スコアボード](https://go-oidc-provider.libraz.net/ja/compliance/ofcs) に掲載しています。

仕様からの意図的な逸脱が 2 つあります。

- **署名は ES256 のみです**。ID トークン、JWT アクセストークン、署名付き UserInfo、JARM レスポンスはすべて ES256 で署名します。段階的な移行の途中ではなく恒久的な方針です。OpenID Connect Core §15.1 は RS256 の実装を必須としているため、RS256 でしか検証できないリライングパーティはサポートしません。検証側はこれより広く、クライアント認証アサーションとリクエストオブジェクトについては RS256 / PS256 / ES256 / EdDSA を受け付けます。
- **DPoP プルーフの検証失敗は OAuth のエラー封筒で返します**。フォームポストでプルーフを受け取るエンドポイントは、RFC 9449 §7 の `invalid_dpop_proof` ではなく `400 invalid_request` を返します。すでに OAuth のエラーコードを処理しているリライングパーティが、DPoP のためだけに分岐を増やさずに済むためです。独自のコードを維持するのは 2 つで、§8 のナンスチャレンジは `DPoP-Nonce` ヘッダとともに `use_dpop_nonce` を返し、保護リソースで拒否されたプルーフは `401 invalid_token` を返します。

どちらの判断理由も、同種の判断とあわせて [Design judgments](https://go-oidc-provider.libraz.net/ja/security/design-judgments) に記録しています。

## ストレージ

[`op/store`](op/store) のサブストアインターフェースを実装すれば任意のバックエンドを利用できます。同梱するアダプタは次のとおりです。

| アダプタ | モジュール | 用途 |
|---|---|---|
| `inmem` | main module | 開発・テスト向けのリファレンス実装。 |
| `sql` | 別モジュール | SQLite / MySQL 8.0+ / PostgreSQL 14+ 向けの `database/sql` アダプタ。エンジンごとのリファレンス DDL を同梱。 |
| `redis` | 別モジュール | 揮発性サブストア専用。TLS と AUTH が無いと起動を拒否する。 |
| `dynamodb` | 別モジュール | サブストアごとに 1 テーブル、トランザクション対応。`Experimental:` マーカー付き。 |
| `composite` | main module | ホット/コールドの振り分け役。永続サブストアと揮発性サブストアを別々のバックエンドへ。 |

[`op/store/contract`](op/store/contract) は内部テストではなく、再利用できる適合ハーネスです。自作バックエンドを渡すと、godoc が規定するセマンティクスを検証し、実装していない任意拡張はスキップします。同梱アダプタもこのスイートで検証しています。

詳しくは [ストレージ構成の選び方](https://go-oidc-provider.libraz.net/ja/use-cases/storage-decision) と [ストアの自作](https://go-oidc-provider.libraz.net/ja/use-cases/byo-store) を参照してください。

## サンプル

[`examples/`](examples/README.md) に動作デモが 44 本あります。オプションや機能 1 つにつき 1 本という構成で、それぞれがドキュメントサイトの [ユースケースページ](https://go-oidc-provider.libraz.net/ja/use-cases/) に対応します。

```sh
(cd examples/01-minimal && GOWORK=off go run -tags example .)
```

各サンプルは開発用の `replace` でチェックアウトを参照する独立モジュールなので、リポジトリのワークスペースを無効にして実行します。`make example-01` も同じことをします。

[`sample/`](sample/README.md) は、オプションを 1 つずつ見せるのではなく、ひとつのアプリケーションとして組み上げたものです。アカウントを自前で持ち、同一プロセスに OP を組み込み、リライングパーティとの往復まで完結させます。ストレージは永続サブストアが MySQL、揮発性サブストアが Redis で、`op/storeadapter/composite` で束ねています。起動は `docker compose -f sample/compose.yaml up -d --build` です。デモンストレーション用であり、公開ホスティングを想定したものではありません。

## コミュニティ

- [SECURITY.md](.github/SECURITY.md) — 脆弱性報告ポリシーとサポート対象バージョン。
- [CONTRIBUTING.md](.github/CONTRIBUTING.md) — コントリビューション手順、Conventional Commits のスコープ、テスト階層の期待値。
- [CODE_OF_CONDUCT.md](.github/CODE_OF_CONDUCT.md) — Contributor Covenant 2.1 と本プロジェクトの通報窓口。

## ライセンス

Apache-2.0 です。[LICENSE](LICENSE) と [NOTICE](NOTICE) を参照してください。サードパーティ依存ライセンスは [`THIRD_PARTY.md`](THIRD_PARTY.md) で追跡し、`go.mod` から `make licenses` で再生成します。
