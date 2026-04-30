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

> **ステータス: pre-v1.0。** v1.0.0 までは minor リリースで public API が
> 変更され得る。タグ付きリリースはまだ存在せず、
> [`CHANGELOG.md`](CHANGELOG.md) は最初のリリース（`v0.1.0`）以降の変更を
> トラックする。

## インストール

```sh
go get github.com/libraz/go-oidc-provider/op@latest
```

Go 1.23+（`go.mod` の宣言に一致）。DB / Redis ドライバを引き込むストア
アダプタはサブモジュールとして公開しており、依存は opt-in するまで
利用者の `go.sum` に入らない。

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

すべて `example` build tag の下にあり、`go test ./...` および本番の
`go.sum` から除外される:

```sh
go run -tags example ./examples/01-minimal
```

### やりたいこと別

| やりたいこと | 起点 |
|---|---|
| 最小構成の OP を立てる | [`01-minimal`](examples/01-minimal/main.go) |
| 典型的な embedder が触る全オプションを見る | [`02-bundle`](examples/02-bundle/main.go) |
| FAPI 2.0 Baseline OP を起動（PAR + JAR + DPoP） | [`03-fapi2`](examples/03-fapi2/main.go), [`50-fapi-tls-jwks`](examples/50-fapi-tls-jwks/main.go) |
| バックエンドサービス向けにトークンを発行（エンドユーザ無し） | [`05-client-credentials`](examples/05-client-credentials/main.go) |
| OIDC と並んで素の OAuth 2.0 を提供 | [`15-oauth2-only`](examples/15-oauth2-only/main.go) |
| 実 DB に永続化（SQLite / MySQL） | [`06-sql-store`](examples/06-sql-store/main.go), [`07-mysql-store`](examples/07-mysql-store/main.go) |
| 揮発状態と耐久状態を hot/cold 分離 | [`08-composite-hot-cold`](examples/08-composite-hot-cold/main.go), [`09-redis-volatile`](examples/09-redis-volatile/main.go) |
| 既定の HTML driver を JSON に差し替える | [`04-custom-interaction`](examples/04-custom-interaction/main.go) |
| login / consent / logout を SPA から駆動 | [`10-react-login`](examples/10-react-login/main.go) |
| consent 画面をカスタマイズ | [`11-custom-consent-ui`](examples/11-custom-consent-ui/main.go) |
| `prompt=select_account`（マルチアカウント）に対応 | [`13-multi-account`](examples/13-multi-account/main.go) |
| 別オリジンの SPA を提供（CORS） | [`14-cors-spa`](examples/14-cors-spa/main.go) |
| プロンプトを多言語化（i18n） | [`16-i18n-locale`](examples/16-i18n-locale/main.go) |
| public-discoverable と internal-only でスコープを分割 | [`12-scopes-public-private`](examples/12-scopes-public-private/main.go) |
| OIDC §5.5 の `claims` リクエストパラメータに対応 | [`17-claims-request`](examples/17-claims-request/main.go) |
| TOTP / リスクベース MFA / captcha / step-up を要求 | [`20-mfa-totp`](examples/20-mfa-totp/main.go), [`21-risk-based-mfa`](examples/21-risk-based-mfa/main.go), [`22-login-captcha`](examples/22-login-captcha/main.go), [`23-step-up`](examples/23-step-up/main.go) |
| ファーストパーティクライアントの consent をスキップ | [`40-first-party-skip-consent`](examples/40-first-party-skip-consent/main.go) |
| RP に自己登録させる（Dynamic Client Registration） | [`41-dynamic-registration`](examples/41-dynamic-registration/main.go) |
| セッション終了を RP に通知（Back-Channel Logout） | [`42-back-channel-logout`](examples/42-back-channel-logout/main.go) |
| RFC 9449 §8 DPoP nonce フローを動かす | [`51-dpop-nonce`](examples/51-dpop-nonce/main.go) |
| Prometheus メトリクスを公開 | [`52-prometheus-metrics`](examples/52-prometheus-metrics/main.go) |

各行は docs サイトの
[/ja/use-cases](https://go-oidc-provider.libraz.net/ja/use-cases/) 配下に
本番形のユースケースページが対応している。

### 番号体系

example の番号は時系列ではなくトピック分類で、空き帯は in-flight または
v1.x 向けの予約:

| 帯 | トピック |
|---|---|
| 00–09 | ブートストラップ、grant 種別、ストレージアダプタ |
| 10–19 | UI、スコープ、SPA、ロケール、claims リクエスト、CORS |
| 20–29 | MFA と認証ルール（TOTP / リスク / captcha / step-up） |
| 30–39 | アイデンティティ連携（予約 — v1.x） |
| 40–49 | ガバナンス: first-party、DCR、Back-Channel Logout |
| 50–59 | 運用: FAPI ヘルパ、メトリクス、トレーシング、DPoP nonce |
| 60–69 | コンプライアンス（予約 — v1.x 後期） |

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
