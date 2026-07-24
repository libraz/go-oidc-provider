# go-oidc-provider

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/go-oidc-provider/ci.yml?branch=main&label=CI)](https://github.com/libraz/go-oidc-provider/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/libraz/go-oidc-provider/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/go-oidc-provider)
[![Release](https://img.shields.io/github/v/release/libraz/go-oidc-provider?include_prereleases&sort=semver&display_name=tag&label=release)](https://github.com/libraz/go-oidc-provider/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)
[![Go Report Card](https://goreportcard.com/badge/github.com/libraz/go-oidc-provider)](https://goreportcard.com/report/github.com/libraz/go-oidc-provider)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-libraz.net-blue?logo=readthedocs&logoColor=white)](https://go-oidc-provider.libraz.net/ja/)

Go 向けの OpenID Connect Provider（Authorization Server）ライブラリです。
`op.New(...)` が返すのは標準の `http.Handler` なので、`net/http` / `chi` /
`gin` など任意のルータにそのままマウントできます。フレームワークに依存せず、
グローバルな状態も持ちません。FAPI 2.0 Baseline / Message Signing への準拠を
主眼に置いています。

> 📘 **[公式ドキュメントサイト](https://go-oidc-provider.libraz.net/ja/)**
> — 概念・ユースケース・セキュリティ方針・適合試験スコアボード・
> オプションリファレンスはすべてドキュメントサイトに集約しています。本 README
> は、ソースツリーの案内とサンプル一覧に絞っています。

> **ステータス: pre-v1.0。** `v0.9.0` が初の公開リリースです。`v1.0.0` までは
> マイナーリリースで公開 API が変わることがあります。
> [`CHANGELOG.md`](CHANGELOG.md) は `v0.9.0` の次のリリース以降の
> 変更点を記録します。

## インストール

```sh
go get github.com/libraz/go-oidc-provider/op@v0.9.6
```

Go 1.25 以上が必要です。DB / Redis ドライバを引き込むストアアダプタは
別モジュールとして公開しているので、明示的に取り込むまで利用者の
`go.sum` に余計な依存は入りません。

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.6
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.6
```

## クイックスタート

`op.New` は `Issuer` / `Store` / `Keyset` を常に必要とします。認可コード
（`authorization_code`）による認可は既定で有効になっており、これを使う場合は
`CookieKeys` も必須です。安全でない構成のままでは起動せずにエラーを返すので、
不完全な設定は構築時に必ず弾かれます。

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

鍵生成・ストア接続・グレースフルシャットダウンまで含めた起動例は
[`examples/01-minimal`](examples/01-minimal/main.go) にあります。詳しくは
[クイックスタート](https://go-oidc-provider.libraz.net/ja/getting-started/install)
と
[必須オプション](https://go-oidc-provider.libraz.net/ja/getting-started/required-options)
を参照してください。

### ローカル開発

既定値は本番向けに調整してあります（https のみ・公開ネットワークのみ）。
`http://127.0.0.1` やループバック上のスタブ RP に対して起動するときは、
次の 2 つのオプションを渡すと、検証ロジックがデモ用の配線を弾かなくなります。

```go
op.WithAllowLocalhostLoopback(),                 // "localhost" という文字列ホストを許可
op.WithAllowInsecureBackchannelLogoutForDev(),   // http://localhost の backchannel_logout_uri を許可
```

どちらも開発・CI 用途に限ったものです。本番の組み込み側ではオフのままにし、
RP は TLS の背後に置いてください。ループバックのアドレスにバインドする
[`examples/`](examples) 配下の例はすべてこの 2 つを使っているので、デモを
本番スタックへ移植するときはこの行を外します。

### FAPI 2.0 Baseline をワンスイッチで

```go
op.WithProfile(profile.FAPI2Baseline) // PAR + JAR + DPoP, ES256, alg ロック
```

宣言したプロファイルと他のオプションが食い違う場合、コンストラクタは起動を
拒否します。詳しくは
[ユースケース: FAPI 2.0 Baseline](https://go-oidc-provider.libraz.net/ja/use-cases/fapi2-baseline)
を参照してください。

## このライブラリがするもの・しないもの

- **`http.Handler` として埋め込む**: フレームワークに依存せず、任意の
  プレフィックスにマウントできます。
- **ユーザモデルとストレージは持ち込み**: 小さな `store.*` サブストアの
  インターフェースを介すだけで、利用者の `users` テーブルを
  ライブラリが直接触ることはありません。
- **ヘッドレスな対話ドライバ**: `op.WithSPAUI` を使えば SPA（React /
  Vue / Svelte / Angular など）にログイン・同意・ログアウトを委譲でき、
  `op.WithConsentUI` で独自テンプレートに差し替えることもできます。
- **監査を起点にした観測性**: 業務イベントは `audit.Emitter` を通じて
  集約され、`op.WithPrometheus(reg)` は厳選したカウンタ群を利用者の
  レジストリに登録します。`/metrics` の公開、リクエスト所要時間を測る
  ミドルウェア、ルータのラップといった処理はライブラリ側では**行いません**。
  これらは組み込み側の責務です。

意図的にスコープから外しているものもあります。IdP ではありません（ユーザ
テーブル・パスワードハッシュ・メール送信は持ちません）。汎用の OAuth2
フレームワークでもありません（OIDC に特化した設計です）。UI フレームワーク
でもありません（既定の HTML ドライバは、OP が無設定でも起動できるように
用意してあります）。詳しくは
[Why this library](https://go-oidc-provider.libraz.net/ja/why) を参照してください。

## 準拠する仕様

OpenID Connect Core 1.0 / OAuth 2.0 (RFC 6749) と Security Best Current
Practices (RFC 9700) / PKCE (RFC 7636), DPoP (RFC 9449), PAR (RFC 9126),
JAR (RFC 9101), JARM, mTLS (RFC 8705) / FAPI 2.0 Baseline / Message
Signing。

各リリースは OpenID Foundation Conformance Suite に対して回帰テストを
かけています。最新のスコアボードは
[適合試験結果ページ](https://go-oidc-provider.libraz.net/ja/compliance/ofcs)、
RFC 別のマトリックスは
[Compliance — RFC matrix](https://go-oidc-provider.libraz.net/ja/compliance/rfc-matrix)
にあります。

## ストレージ

[`op/store`](op/store) のサブストアインターフェースを実装すれば、任意の
バックエンドを利用できます。同梱するアダプタは次のとおりです。

| アダプタ | モジュールパス | 用途 |
|---|---|---|
| `inmem` | `op/storeadapter/inmem` | リファレンス実装。開発・テスト向け。[`op/store/contract`](op/store/contract) のコントラクトハーネスはこれに対して走る。 |
| `sql` | `op/storeadapter/sql` | SQLite / MySQL 8.0+ / PostgreSQL 14+ 向けの `database/sql` アダプタ。**別モジュール。** `go test -tags=testcontainers` で全サブストアを実エンジン（testcontainers）に対して走らせる。 |
| `redis` | `op/storeadapter/redis` | 揮発性のサブストア（`InteractionStore` / `ConsumedJTIStore` / `SessionStore`）向け。**別モジュール。** Session は Redis TTL に従うため、grant / credential は durable backend と合成する。TLS（`rediss://`）と AUTH が無いと起動を拒否する（明示的な `WithDevModeAllowPlaintext` のみ例外）。 |
| `composite` | `op/storeadapter/composite` | ホット/コールドの振り分け役。永続サブストアを一方のバックエンド、揮発性を他方へ振り分けつつ、トランザクショナルクラスタの不変条件を強制する。 |

**認証ファクタのストアは組み込み側が所有します。** 上記のアダプタが永続化
するのは OIDC/OAuth のサブストアです。ログインフローが要求しうるファクタ
（TOTP・パスキー・リカバリコード・メール OTP・ブルートフォース対策の
ロックアウトカウンタ）は別のサブストア（`store.TOTPStore` /
`store.PasskeyStore` / `store.RecoveryStore` / `store.EmailOTPStore` /
`store.AuthnLockoutStore`）で、認証コンポーネントの設定を通じて注入します。
スキーマと暗号鍵の管理がデプロイごとの判断になるためです。これらを実装
しているのは `inmem` リファレンスだけなので、本番デプロイでは独自の永続実装
を用意します。
[`examples/27-durable-mfa-store`](examples/27-durable-mfa-store/main.go) は
コピーして流用できるテンプレートで、コアアダプタと 1 つの DB を共有する
SQL バックエンドの `store.TOTPStore` 実装です。

DynamoDB アダプタは v1.x で別モジュールとして提供予定です。背景は
[Operations — multi-instance](https://go-oidc-provider.libraz.net/ja/operations/multi-instance)
を参照してください。

## サンプル

動作デモは [`examples/`](examples/README.md) 配下にあります。目的別の対応表、
番号レンジの割り振り、`07-mysql-store` / `09-redis-volatile` 用の
docker スタック手順は、そちらの索引（英語）にまとめています。各行は
ドキュメントサイトの
[ユースケース一覧](https://go-oidc-provider.libraz.net/ja/use-cases/)
配下のページに対応します。

```sh
(cd examples/01-minimal && go run -tags example .)
```

## コミュニティ

- [SECURITY.md](SECURITY.md) — 脆弱性報告ポリシーとサポート対象
  バージョン。
- [CONTRIBUTING.md](CONTRIBUTING.md) — コントリビューション手順、
  Conventional Commits のスコープ、テスト階層の期待値。
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1 と
  本プロジェクトの通報窓口。

## ライセンス

Apache-2.0 です。[LICENSE](LICENSE) と [NOTICE](NOTICE) を参照してください。
サードパーティ依存ライセンスは [`THIRD_PARTY.md`](THIRD_PARTY.md) で追跡し、
`go.mod` から `make licenses` で再生成します。
