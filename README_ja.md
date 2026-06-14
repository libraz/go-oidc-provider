# go-oidc-provider

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/go-oidc-provider/ci.yml?branch=main&label=CI)](https://github.com/libraz/go-oidc-provider/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/libraz/go-oidc-provider/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/go-oidc-provider)
[![Release](https://img.shields.io/github/v/release/libraz/go-oidc-provider?include_prereleases&sort=semver&display_name=tag&label=release)](https://github.com/libraz/go-oidc-provider/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)
[![Go Report Card](https://goreportcard.com/badge/github.com/libraz/go-oidc-provider)](https://goreportcard.com/report/github.com/libraz/go-oidc-provider)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-libraz.net-blue?logo=readthedocs&logoColor=white)](https://go-oidc-provider.libraz.net/ja/)

Go 向けの OpenID Connect Provider（Authorization Server）ライブラリ。
`op.New(...)` は標準の `http.Handler` を返すので、`net/http` / `chi` /
`gin` など任意のルータにそのままマウントできる。フレームワーク非依存・
グローバル状態なし。FAPI 2.0 Baseline / Message Signing への準拠を主要
ターゲットとする。

> 📘 **[公式ドキュメントサイト](https://go-oidc-provider.libraz.net/ja/)**
> — 概念・ユースケース・セキュリティ方針・適合試験スコアボード・
> オプションリファレンスはすべて docs サイトに集約。本 README は
> ソースツリーの索引とサンプル一覧として機能する。

> **ステータス: pre-v1.0。** `v0.9.0` が初の公開リリース。`v1.0.0` までは
> minor リリースで public API が変更されることがある。
> [`CHANGELOG.md`](CHANGELOG.md) は `v0.9.0` の次のリリース以降の
> 変更点を記録する。

## インストール

```sh
go get github.com/libraz/go-oidc-provider/op@v0.9.3
```

Go 1.25+。DB / Redis ドライバを引き込むストアアダプタはサブモジュール
として公開しているため、明示的に取り込むまで利用者の `go.sum` に
依存は入らない。

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.3
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.3
```

## クイックスタート

`op.New` の最小必須オプションは 4 つ — `Issuer`, `Store`, `Keyset`,
32 バイトの `CookieKeys`。安全でない構成のままでは起動せずエラーを返すため、
不完全な設定は構築時に必ず失敗する。

```go
handler, err := op.New(
    op.WithIssuer("https://idp.example.com"),
    op.WithStore(inmem.New()),
    op.WithKeyset(op.Keyset{{KeyID: "k1", Signer: priv}}),
    op.WithCookieKeys(cookieKey), // 32 バイト, AES-256-GCM
)
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", handler))
```

鍵生成・ストア接続・graceful shutdown まで含めた起動例は
[`examples/01-minimal`](examples/01-minimal/main.go) にある。詳細は
[クイックスタート](https://go-oidc-provider.libraz.net/ja/getting-started/install)
と
[必須オプション](https://go-oidc-provider.libraz.net/ja/getting-started/required-options)
を参照。

### FAPI 2.0 Baseline をワンスイッチで

```go
op.WithProfile(profile.FAPI2Baseline) // PAR + JAR + DPoP, ES256, alg ロック
```

宣言したプロファイルと他のオプションが衝突した場合、コンストラクタは
起動を拒否する。詳細は
[ユースケース: FAPI 2.0 Baseline](https://go-oidc-provider.libraz.net/ja/use-cases/fapi2-baseline)
を参照。

## このライブラリがするもの・しないもの

- **`http.Handler` として埋め込む**: フレームワーク非依存、任意の
  プレフィックスでマウント可能。
- **ユーザモデルとストレージは持ち込み**: 小さな `store.*` substore
  インターフェースを介すのみで、利用者の `users` テーブルを
  ライブラリが直接参照することはない。
- **ヘッドレスな interaction driver**: `op.WithSPAUI` で SPA（React /
  Vue / Svelte / Angular など）に login / consent / logout を委譲、
  `op.WithConsentUI` で独自テンプレートを差し替え可能。
- **audit を起点とした観測性**: 業務イベントは `audit.Emitter` 経由で
  集約され、`op.WithPrometheus(reg)` は厳選したカウンタ群を利用者の
  registry に登録する。`/metrics` のマウント、request-duration ミドル
  ウェア、ルータの wrap などはライブラリ側では**行わない** — embedder
  の責務とする。

意図的にスコープ外: IdP ではない（ユーザテーブル・パスワードハッシュ・
メール送信は持たない）、汎用 OAuth2 フレームワークではない（OIDC に
特化した設計）、UI フレームワークではない（既定の HTML driver は OP が
無設定で起動するためにある）。詳細は
[Why this library](https://go-oidc-provider.libraz.net/ja/why) を参照。

## 準拠する仕様

OpenID Connect Core 1.0 / OAuth 2.0 (RFC 6749) と Security Best Current
Practices (RFC 9700) / PKCE (RFC 7636), DPoP (RFC 9449), PAR (RFC 9126),
JAR (RFC 9101), JARM, mTLS (RFC 8705) / FAPI 2.0 Baseline / Message
Signing。

各リリースは OpenID Foundation Conformance Suite に対して回帰テストを
実施している。最新スコアボードは
[適合試験結果ページ](https://go-oidc-provider.libraz.net/ja/compliance/ofcs)、
RFC 別のマトリックスは
[Compliance — RFC matrix](https://go-oidc-provider.libraz.net/ja/compliance/rfc-matrix)
にある。

## ストレージ

[`op/store`](op/store) の substore インターフェースを実装すれば任意の
バックエンドを利用できる。同梱アダプタ:

| アダプタ | モジュールパス | 用途 |
|---|---|---|
| `inmem` | `op/storeadapter/inmem` | リファレンス実装。dev / test 向け。[`op/store/contract`](op/store/contract) のコントラクトハーネスはこれに対して走る。 |
| `sql` | `op/storeadapter/sql` | SQLite / MySQL 8.0+ / PostgreSQL 14+ 向けの `database/sql` アダプタ。**サブモジュール。** `go test -tags=testcontainers` で全 substore を実エンジン（testcontainers）に対して走らせる。 |
| `redis` | `op/storeadapter/redis` | volatile substore（`InteractionStore` / `ConsumedJTIStore`）向け。**サブモジュール。** TLS（`rediss://`）と AUTH 無しでは起動を拒否する（明示的な `WithDevModeAllowPlaintext` のみ例外）。 |
| `composite` | `op/storeadapter/composite` | hot/cold スプリッタ。durable substore を一方の backend、volatile を他方に振り分けつつ、transactional-cluster invariant を強制する。 |

DynamoDB アダプタは v1.x で追加サブモジュールとして提供予定。背景は
[Operations — multi-instance](https://go-oidc-provider.libraz.net/ja/operations/multi-instance)
を参照。

## サンプル

動作デモは [`examples/`](examples/README.md) 配下にある。目的別の対応表、
番号レンジの割り振り、`07-mysql-store` / `09-redis-volatile` 用の
docker スタック手順はそちらの index（英語）にまとめてある。各行は
docs サイトの
[ユースケース一覧](https://go-oidc-provider.libraz.net/ja/use-cases/)
配下のページに対応する。

```sh
go run -tags example ./examples/01-minimal
```

## コミュニティ

- [SECURITY.md](SECURITY.md) — 脆弱性報告ポリシーとサポート対象
  バージョン。
- [CONTRIBUTING.md](CONTRIBUTING.md) — コントリビューション手順、
  Conventional Commits のスコープ、テスト階層の期待値。
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1 と
  本プロジェクトの通報窓口。

## ライセンス

Apache-2.0。[LICENSE](LICENSE) と [NOTICE](NOTICE) を参照。サードパーティ
依存ライセンスは [`THIRD_PARTY.md`](THIRD_PARTY.md) で追跡し、`go.mod`
から `make licenses` で再生成される。
