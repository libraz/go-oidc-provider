# go-oidc-provider

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)

Go 製の OpenID Connect Provider（Authorization Server）ライブラリ。
`op.New(...)` は標準の `http.Handler` を返し、`net/http` / `chi` / `gin`
などの任意のルータにマウントできる。フレームワーク依存なし、グローバル
状態なし。FAPI 2.0 Baseline / Message Signing をターゲットにしている。

> **ドキュメント:** [go-oidc-provider.libraz.net](https://go-oidc-provider.libraz.net/ja/)
> — 概念、ユースケース、セキュリティポスチャ、適合試験結果、オプション
> リファレンスはすべて docs サイトに集約。本 README はソースツリーの地図と
> サンプルインベントリ。

> **ステータス: pre-v1.0。** `v0.9.0` が初の公開リリース。`v1.0.0` までは
> minor リリースで public API が変更され得る。
> [`CHANGELOG.md`](CHANGELOG.md) は `v0.9.0` 以降の変更をトラックする。

## インストール

```sh
go get github.com/libraz/go-oidc-provider/op@v0.9.0
```

Go 1.23+（`go.mod` の宣言に一致）。DB / Redis ドライバを引き込むストア
アダプタはサブモジュールとして公開しており、依存は opt-in するまで
利用者の `go.sum` に入らない:

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0
```

## クイックスタート

`op.New` の最小必須オプションは 4 つ — `Issuer`, `Store`, `Keyset`, 32 バイトの
`CookieKey`。コンストラクタは安全でない構成では起動せずエラーを返すため、
中途半端な設定は構築時に落ちる。

```go
handler, err := op.New(
    op.WithIssuer("https://idp.example.com"),
    op.WithStore(inmem.New()),
    op.WithKeyset(op.Keyset{{KeyID: "k1", Signer: priv}}),
    op.WithCookieKey(cookieKey), // 32 バイト, AES-256-GCM
)
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", handler))
```

鍵生成・ストア接続・graceful shutdown まで含めた起動例は
[`examples/01-minimal`](examples/01-minimal/main.go) にある。詳細は
[クイックスタート](https://go-oidc-provider.libraz.net/ja/getting-started/install) /
[必須オプション](https://go-oidc-provider.libraz.net/ja/getting-started/required-options)。

### FAPI 2.0 Baseline をワンスイッチで

```go
op.WithProfile(profile.FAPI2Baseline) // PAR + JAR + DPoP, ES256, alg ロック
```

宣言したプロファイルと他のオプションが衝突した場合、コンストラクタは
起動を拒否する。詳細は
[ユースケース: FAPI 2.0 Baseline](https://go-oidc-provider.libraz.net/ja/use-cases/fapi2-baseline)。

## このライブラリがするもの・しないもの

- **`http.Handler` として埋め込む**: フレームワーク非依存、任意のプレ
  フィックスでマウント可能。
- **ユーザモデルとストレージは持ち込み**: 小さな `store.*` substore
  インターフェースを介すのみで、`users` テーブルを直接参照しない。
- **ヘッドレスな interaction driver**: `op.WithSPAUI` で SPA（React /
  Vue / Svelte / Angular など、フレームワーク不問）に login / consent /
  logout を委譲、`op.WithConsentUI` で独自テンプレートを差し替え可能。
- **audit-first な観測性**: 業務イベントは `audit.Emitter` 経由で集約され、
  `op.WithPrometheus(reg)` は curated counter set を利用者の registry に
  登録する。`/metrics` のマウント、request-duration ミドルウェア、
  ルータの wrap などはライブラリ側では**やらない** — embedder の責務。

意図的にスコープ外: IdP ではない（ユーザテーブル・パスワードハッシュ・
メール送信は持たない）、汎用 OAuth2 フレームワークではない（OIDC に倒した
設計）、UI キットではない（既定の HTML driver は OP が無設定で起動する
ためにある）。詳細は
[Why this library](https://go-oidc-provider.libraz.net/ja/why)。

## 準拠する仕様

OpenID Connect Core 1.0 / OAuth 2.0 (RFC 6749) と Security Best Current
Practices (RFC 9700) / PKCE (RFC 7636), DPoP (RFC 9449), PAR (RFC 9126),
JAR (RFC 9101), JARM, mTLS (RFC 8705) / FAPI 2.0 Baseline / Message Signing。

各リリースは OpenID Foundation Conformance Suite に対して回帰テストを
実施している。最新スコアボードは
[docs サイト](https://go-oidc-provider.libraz.net/ja/compliance/ofcs)、
RFC 別のマトリックスは
[Compliance — RFC matrix](https://go-oidc-provider.libraz.net/ja/compliance/rfc-matrix)。

## ストレージ

[`op/store`](op/store) の substore インターフェースを実装すれば任意の
バックエンドを使える。同梱アダプタ:

| アダプタ | モジュールパス | 用途 |
|---|---|---|
| `inmem` | `op/storeadapter/inmem` | リファレンス実装。dev / test 向け。[`op/store/contract`](op/store/contract) のコントラクトハーネスはこれに対して走る。 |
| `sql` | `op/storeadapter/sql` | SQLite / MySQL 8.0+ / PostgreSQL 14+ 向けの `database/sql` アダプタ。**サブモジュール。** `go test -tags=testcontainers` で全 substore を実エンジン（testcontainers）に対して走らせる。 |
| `redis` | `op/storeadapter/redis` | volatile substore（`InteractionStore` / `ConsumedJTIStore`）向け。**サブモジュール。** TLS（`rediss://`）と AUTH 無しでは起動を拒否する（明示的な `WithDevModeAllowPlaintext` のみ例外）。 |
| `composite` | `op/storeadapter/composite` | hot/cold スプリッタ。durable substore を一方の backend、volatile を他方に振り分けつつ、transactional-cluster invariant を強制する。 |

DynamoDB アダプタは v1.x で追加サブモジュールとして予定。背景は
[Operations — multi-instance](https://go-oidc-provider.libraz.net/ja/operations/multi-instance)。

## サンプル

動作デモは [`examples/`](examples/README.md) 配下にあり、目的別表・番号
帯・`07-mysql-store` / `09-redis-volatile` の docker スタック手順は
そちらの index（English）に集約。各行は docs サイトの
[/ja/use-cases](https://go-oidc-provider.libraz.net/ja/use-cases/) 配下の
ユースケースページに対応する。

```sh
go run -tags example ./examples/01-minimal
```

## コミュニティ

- [SECURITY.md](SECURITY.md) — 脆弱性報告ポリシーとサポート対象バージョン。
- [CONTRIBUTING.md](CONTRIBUTING.md) — コントリビューション手順、
  Conventional Commits のスコープ、テスト階層の期待値。
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1 と
  本プロジェクトの通報窓口。

## ライセンス

Apache-2.0。[LICENSE](LICENSE) と [NOTICE](NOTICE) を参照。サードパーティ
依存ライセンスは [`THIRD_PARTY.md`](THIRD_PARTY.md) で追跡し、`go.mod` から
`make licenses` で再生成される。
