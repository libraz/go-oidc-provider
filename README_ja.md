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

> **ステータス: `v1.0.0`。** 本リリース以降、公開 `op` API は
> [Semantic Versioning](https://semver.org/spec/v2.0.0.html) に厳密に従います。
> 唯一の例外は godoc に `Experimental:` マーカーを持つシンボルで、その一覧は
> [`api/experimental.txt`](api/experimental.txt) に機械生成されます。
> `make verify` が再生成して差分を検査するため、例外の範囲がレビューを
> 経ずに広がることはありません。採用前に把握しておくべき点として、例外に
> あたるのは認証ステップのシーム（`LoginFlow` / `WithLoginFlow` /
> `WithAuthenticators` とその周辺フック）、interaction の UI 型、および
> IETF ドラフトを追随している Grant Management です。プロトコル面・
> ストレージインタフェース・その他のオプションはすべて安定扱いです。
> [`CHANGELOG.md`](CHANGELOG.md) は
> `v0.9.0` の次のリリース以降の変更点を記録します。
>
> 本プロジェクトは個人が余暇で開発しているものであり、ベンダー製品では
> ありません。リリースごとに OpenID Foundation の適合試験スイートで
> 回帰検証していますが、正式な認定は受けておらず、サポートは
> ベストエフォートです。

## インストール

```sh
go get github.com/libraz/go-oidc-provider/op@v1.0.0
```

Go 1.25 以上が必要です。DB / Redis / AWS SDK のドライバを引き込むストア
アダプタは別モジュールとして公開しているので、明示的に取り込むまで
利用者の `go.sum` に余計な依存は入りません。

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.0.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.0.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.0.0
```

## クイックスタート

`op.New` は `Issuer` / `Store` / `Keyset` を常に必要とします。認可コード
（`authorization_code`）による認可は既定で有効になっており、これを使う場合は
`CookieKeys` も必須です。安全でない構成のままでは起動せずにエラーを返すので、
不完全な設定は構築時に必ず弾かれます。

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

`WithLoginFlow` はブラウザセッションの認証方法を宣言するオプションです。
`client_credentials` だけを提供する OP には認証すべきユーザーがいないため必須
オプションではありません。ただし認可エンドポイントを持つ構成でこれを省くと、
構築自体は成功する一方で要求すべき資格情報が無く、対話を必要とする最初の
リクエストが `server_error` を返します。まず `op.PrimaryPassword` から始め、
追加の要素はルールとして重ねてください
（[`examples/20-mfa-totp`](examples/20-mfa-totp/main.go) が同じフローに第二要素を
合成する例です）。

鍵生成・ストア接続・グレースフルシャットダウンまで含めた起動例は
[`examples/01-minimal`](examples/01-minimal/main.go) にあります。詳しくは
[クイックスタート](https://go-oidc-provider.libraz.net/ja/getting-started/install)
と
[必須オプション](https://go-oidc-provider.libraz.net/ja/getting-started/required-options)
を参照してください。

### ローカル開発

既定値は本番向けに調整してあります（https のみ・公開ネットワークのみ）が、
ループバックの IP リテラルは最初から除外規定に入っています。つまり
`http://127.0.0.1:8080` は、オプションを 1 つも渡さない状態で issuer としても
`redirect_uri` のホストとしても有効です。[`examples/`](examples) 配下の例の
大半が下記のどちらのオプションも必要としないのはこのためで、これらは一貫して
`127.0.0.1` にバインドしています。

IP リテラルでは足りないケース向けに、次の 2 つの限定的なオプションがあります。

```go
op.WithAllowLocalhostLoopback(),                 // "localhost" という文字列ホストを許可
op.WithAllowInsecureBackchannelLogoutForDev(),   // http:// の backchannel_logout_uri を許可
```

`WithAllowLocalhostLoopback` が要るのは、配線のどこかを `127.0.0.1` ではなく
`localhost` と綴らなければならない場合だけです。44 例のうち 9 例が使っており、
その多くはスタブ RP が `http://localhost:…/callback` を `redirect_uri` として
登録するためです。[`29-passkey`](examples/29-passkey/main.go) だけは理由が別で、
WebAuthn の Relying Party ID はドメインである必要があり、ブラウザが IP
リテラルを拒否するからです。この文字列ホストが既定の除外規定に入っていないのは、
`localhost` の名前解決が乗っ取られうるためです（RFC 8252 §7.3）。

`WithAllowInsecureBackchannelLogoutForDev` が要るのは、平文 http の
`backchannel_logout_uri` を登録する場合だけで、これを使うのは 44 例のうち 1 例
（[`42-back-channel-logout`](examples/42-back-channel-logout/main.go)）です。

どちらも開発・CI 用途に限ったものです。検証ロジックに実際に弾かれたのでない
限り追加せず、デモを本番スタックへ移植するときは外してください。

### セキュリティプロファイルをワンスイッチで

```go
op.WithProfile(profile.Baseline)      // OAuth 2.1: code 要求すべてに PKCE 必須
op.WithProfile(profile.FAPI2Baseline) // PAR + JAR + DPoP, ES256, alg ロック
```

プロファイルを宣言しないこと自体もひとつの構成です。それは OpenID Connect
Core 1.0 の形であり、RFC 7636 より古い仕様なので confidential client の PKCE
は任意のままになります。`profile.Baseline` は、その緩い姿勢を黙って引き継ぐ
のではなく、厳しい姿勢を選んだと明示するための宣言です。

宣言したプロファイルと他のオプションが食い違う場合、コンストラクタは起動を
拒否します。OP が処理できるよう配線されていないフローをプロファイルが名指し
している場合も同様です。構築に成功した Provider は `startup.profile` 監査
レコードを 1 件発行し、宣言したプロファイル・フィーチャ・grant と、それらが
解決したポリシー値を記録します。詳しくは
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

コア: OpenID Connect Core 1.0、OAuth 2.0 (RFC 6749) と Security Best Current
Practices (RFC 9700)、OpenID Connect Discovery 1.0 と OAuth 2.0 Authorization
Server Metadata (RFC 8414)。

リクエストとトークンの堅牢化: PKCE (RFC 7636)、DPoP (RFC 9449)、PAR
(RFC 9126)、JAR (RFC 9101)、JARM、mTLS (RFC 8705)、認可レスポンスの issuer
識別 (RFC 9207)、Rich Authorization Requests (RFC 9396)、ステップアップ認証
(RFC 9470)、FAPI 2.0 Baseline / Message Signing。

追加の grant: Device Authorization Grant (RFC 8628)、Client-Initiated
Backchannel Authentication (CIBA Core 1.0)、Token Exchange (RFC 8693)。
`op.WithCustomGrant` で組み込み側が定義した grant も追加できます。

トークンとクライアントのライフサイクル: JWT プロファイルのアクセストークン
(RFC 9068)、トークン失効 (RFC 7009)、トークンイントロスペクション (RFC 7662)、
Dynamic Client Registration とその管理 API (RFC 7591 / RFC 7592、OpenID
Connect Dynamic Client Registration 1.0)。

セッションの終了: OpenID Connect RP-Initiated Logout 1.0 と Back-Channel
Logout 1.0。Front-Channel Logout は実装していません。

各リリースは OpenID Foundation Conformance Suite に対して回帰テストを
かけています。最新のスコアボードは
[適合試験結果ページ](https://go-oidc-provider.libraz.net/ja/compliance/ofcs)、
RFC 別のマトリックスは
[Compliance — RFC matrix](https://go-oidc-provider.libraz.net/ja/compliance/rfc-matrix)
にあります。

**意図的な仕様からの逸脱がひとつあります。署名は ES256 のみです。**
ID トークン、JWT アクセストークン、署名付き UserInfo、JARM レスポンスは
すべて ES256 で署名します。これは段階的な移行の途中ではなく恒久的な方針です。
OpenID Connect Core §15.1 は RS256 の実装を必須としているため、これは仕様の
文言からの意図的な逸脱にあたります。RS256 でしか検証できないリライング
パーティはサポートしません。引き換えに得られるのは、検証済みの曲線ひとつだけを
扱い、アルゴリズムのネゴシエーションを持たず、したがって防ぐべきダウングレード
経路も存在しないという性質です。ES256 は本ライブラリが対象とする FAPI 2.0
プロファイルの第一級アルゴリズムであり、そのプロファイルは RS256 自体を
禁じています。なお**検証**側はこれより広く、クライアント認証アサーションと
リクエストオブジェクトについては RS256 / PS256 / ES256 / EdDSA をいずれも
受け付けます。

**もうひとつの逸脱として、DPoP プルーフの検証失敗は OAuth のエラー封筒で
返します。** RFC 9449 §7 は `invalid_dpop_proof` を定めていますが、フォーム
ポストでプルーフを受け取るエンドポイント（トークン、PAR、デバイス認可、CIBA）
はいずれも HTTP 400 と `error=invalid_request` を返します。これらの
エンドポイントが他の失敗ですでに使っている封筒と同じなので、OAuth の
エラーコードを見ているリライングパーティは DPoP のためだけに新しいコード種別を
扱う必要がありません。`error_description` は失敗の系統（`DPoP proof
malformed` / `DPoP proof signature invalid` / `DPoP proof does not bind to
this request` / `DPoP proof iat outside acceptable window` / `DPoP proof
replayed`）までは区別しますが、それ以上の細かい原因は示しません。どの検証段階
まで到達したかを攻撃者に教えないためです。ただし次の 2 つはクライアントが
判断に使う情報を失うため、独自のコードを維持します。§8 のナンスチャレンジは
`error=use_dpop_nonce` と `DPoP-Nonce` レスポンスヘッダを返し、再試行可能で
あることを終端的な失敗と区別できるようにします。保護リソースで拒否された
プルーフは、その面を規定する Bearer トークンのエラー規則に従って
`401 invalid_token` を返します。

## ストレージ

[`op/store`](op/store) のサブストアインターフェースを実装すれば、任意の
バックエンドを利用できます。同梱するアダプタは次のとおりです。

| アダプタ | モジュールパス | 用途 |
|---|---|---|
| `inmem` | `op/storeadapter/inmem` | リファレンス実装。開発・テスト向け。[`op/store/contract`](op/store/contract) のコントラクトハーネスはこれに対して走る。 |
| `sql` | `op/storeadapter/sql` | SQLite / MySQL 8.0+ / PostgreSQL 14+ 向けの `database/sql` アダプタ。**別モジュール。** `go test -tags=testcontainers` で全サブストアを実エンジン（testcontainers）に対して走らせる。 |
| `redis` | `op/storeadapter/redis` | 揮発性のサブストア（`InteractionStore` / `ConsumedJTIStore` / `SessionStore`）向け。**別モジュール。** Session は Redis TTL に従うため、grant / credential は durable backend と合成する。TLS（`rediss://`）と AUTH が無いと起動を拒否する（明示的な `WithDevModeAllowPlaintext` のみ例外）。 |
| `dynamodb` | `op/storeadapter/dynamodb` | DynamoDB アダプタ。サブストアごとに 1 テーブル。書き込みをバッファし `TransactWriteItems` 1 回でコミットすることで `store.Transactional` を満たすため、ブラウザ認可コードフローを DynamoDB 単体で提供できる。**別モジュール。** コントラクトハーネスは `amazon/dynamodb-local` に対して走る（`go test -tags=testcontainers`）。`Experimental:` マーカー付きのため [`api/experimental.txt`](api/experimental.txt) に載り、SemVer の約束の対象外。 |
| `composite` | `op/storeadapter/composite` | ホット/コールドの振り分け役。永続サブストアを一方のバックエンド、揮発性を他方へ振り分けつつ、トランザクショナルクラスタの不変条件を強制する。 |

**自作バックエンドはコントラクトスイートで検証できます。**
[`op/store/contract`](op/store/contract) は内部テストではなく再利用可能な適合
ハーネスです。自作バックエンドを渡すと、godoc が規定するセマンティクス
（sentinel エラー、単回消費、bearer secret のハッシュ保存）を検証し、実装して
いない任意拡張はスキップします。同梱アダプタもこのスイートで検証しています。
OP がどの拡張を要求し、その要求が何によって有効になるかは
[`op/store` のパッケージドキュメント](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op/store)
に表としてまとめてあります。必須拡張が欠けている場合はリクエスト時ではなく
`op.New` が構築時に拒否します。

**認証ファクタのストア。** ログインフローが要求しうるファクタ（TOTP・
パスキー・リカバリコード・メール OTP・要素横断のブルートフォースロック
アウトカウンタ）は別のサブストア（`store.TOTPStore` /
`store.PasskeyStore` / `store.RecoveryStore` / `store.EmailOTPStore` /
`store.AuthnLockoutStore`）で、`store.Store` 経由ではなく認証コンポーネントの
設定を通じて注入します。第二要素を一切使わないデプロイに、これらのテーブルの
用意を強いないためです。`inmem` / `sql` / `dynamodb` の 3 アダプタがいずれも
実装しており、アクセサ名も揃えてあるので（`TOTPs()` / `Passkeys()` /
`RecoveryCodes()` / `EmailOTPs()` / `AuthnLockouts()`）、そのまま差し替え
られます。

```go
op.WithAuthnLockoutStore(st.AuthnLockouts())
op.StepTOTP{Store: st.TOTPs(), EncryptionKey: mfaKey}
```

これらの契約も他と同じハーネス（`contract.RunTOTPs` / `RunPasskeys` /
`RunRecoveryCodes` / `RunEmailOTPs` / `RunAuthnLockouts`）で固定してあるため、
自作実装も同じ手順で検証できます。同梱していないバックエンドを一から書く例は
[`examples/26-byo-store-from-scratch`](examples/26-byo-store-from-scratch/main.go)
に、同梱アダプタを使う場合（ファクタ用テーブルとコアテーブルを 1 つの DB に置き、
マイグレーションもコネクションプールも 1 つで済ませる形）は
[`examples/27-durable-mfa-store`](examples/27-durable-mfa-store/main.go)
にあります。

**スキーマの適用。** `sql` アダプタはエンジンごとのリファレンス DDL を
[`op/storeadapter/sql/schema/{sqlite,mysql,postgres}/v1.sql`](op/storeadapter/sql/schema)
に同梱しています。ライブラリ採用前に DBA にレビューさせたい場合は、
リポジトリから直接読めます。`Store.Schema()` は設定中の方言の DDL を
`WithNaming` によるテーブル名変更を適用した状態で返すので、手元の
マイグレーションツールに流し込んだり、既存スキーマとの差分を取ったりできます。
`Store.Migrate(ctx)` は同じ DDL を接続中の DB に直接適用しますが、これは
サンプルとテストが使う開発用の近道であり、本番のマイグレーションは利用者側の
ツールで管理する想定です。認証ファクタのテーブルも同じ DDL に含まれるため、
第二要素を有効にするために別途マイグレーションを足す必要はありません。
DynamoDB も同じ二段構えで、`TableDefinitions()` が CloudFormation や
Terraform に渡すキースキーマを返し、`CreateTables(ctx)` が開発・テスト用に
テーブルを作成します。

## サンプル

動作デモは [`examples/`](examples/README.md) 配下にあります。目的別の対応表、
番号レンジの割り振り、`07-mysql-store` / `09-redis-volatile` /
`17-spa-composite-store` / `18-dynamodb-store` 用の docker スタック手順は、
そちらの索引（英語）にまとめています。各行は
ドキュメントサイトの
[ユースケース一覧](https://go-oidc-provider.libraz.net/ja/use-cases/)
配下のページに対応します。

```sh
(cd examples/01-minimal && GOWORK=off go run -tags example .)
```

各サンプルは開発用の `replace` でチェックアウトを参照する独立モジュールなので、
リポジトリのワークスペースを無効にして実行します。`make example-01` も同じ
ことをします。

## リファレンスアプリケーション

[`sample/`](sample/README.md) は番号付きサンプルの対になるものです。オプションを
1 つずつ見せるのではなく、ひとつのアプリケーションとして組み上げてあります。
アカウントを自前で持ち、同一プロセスに OP を組み込み、リライングパーティとの
往復まで完結させます。ストレージは永続サブストアが MySQL、揮発性サブストアが
Redis で、`op/storeadapter/composite` で束ねています。起動は
`docker compose -f sample/compose.yaml up -d --build` です。これはデモンスト
レーション用であり、公開ホスティングを想定したものではありません。

## コミュニティ

- [SECURITY.md](.github/SECURITY.md) — 脆弱性報告ポリシーとサポート対象
  バージョン。
- [CONTRIBUTING.md](.github/CONTRIBUTING.md) — コントリビューション手順、
  Conventional Commits のスコープ、テスト階層の期待値。
- [CODE_OF_CONDUCT.md](.github/CODE_OF_CONDUCT.md) — Contributor Covenant 2.1 と
  本プロジェクトの通報窓口。

## ライセンス

Apache-2.0 です。[LICENSE](LICENSE) と [NOTICE](NOTICE) を参照してください。
サードパーティ依存ライセンスは [`THIRD_PARTY.md`](THIRD_PARTY.md) で追跡し、
`go.mod` から `make licenses` で再生成します。
