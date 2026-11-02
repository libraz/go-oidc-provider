package oidcredis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Shared Signals Framework transmitter state.
//
// Key layout, every key under the adapter prefix:
//
//	ssf:streams                    HASH  stream ID -> JSON stream record
//	ssf:stream-clients             HASH  client ID -> stream ID
//	ssf:event:<jti>                HASH  one queued SET (fields below)
//	ssf:stream-events:<streamID>   SET   JTIs queued for the stream
//	ssf:stream-verify:<streamID>   STRING JTI of the stream's queued verification
//	ssf:stream-updated:<streamID>  STRING JTI of the stream's queued stream-updated
//	ssf:stream-due:<streamID>      ZSET  JTI scored by next_attempt_at, push && !held only
//	ssf:stream-ready:<streamID>    ZSET  JTI scored 0, poll && !held only
//	ssf:due                        ZSET  stream ID scored by its earliest stream-due score
//	ssf:expiry                     ZSET  JTI scored by expires_at
//
// Instants are decimal Unix microseconds, exact in a Lua/ZSET double.
// Every event mutation runs as one Lua script, so the due sets, the expiry
// set and the per-stream indexes never disagree with the event hashes, and
// a stream Update and an Enqueue checking the stream's state are serial.
// ClaimDue and Pending read only the per-stream due and ready sets, so
// their cost follows the events they return, not the stream's backlog.
// The scripts derive the event keys from the prefix passed as ARGV[1];
// that is sound because the adapter talks to one Redis node, never a
// cluster. None of these keys carries a TTL: queue lifetime is
// ExpiresAt, enforced by DeleteExpired.

// ssfDeleteExpiredBatch caps how many events one DeleteExpired script
// removes, so a backlog does not block the server in one long script.
const ssfDeleteExpiredBatch = 512

// ssfLuaPrelude defines the key builders and the single event-removal
// path every event script shares.
const ssfLuaPrelude = `
local P = ARGV[1]
local function ev_key(jti) return P .. "ssf:event:" .. jti end
local function idx_key(sid) return P .. "ssf:stream-events:" .. sid end
local function sdue_key(sid) return P .. "ssf:stream-due:" .. sid end
local function ready_key(sid) return P .. "ssf:stream-ready:" .. sid end
local ctl_prefix = {verification = "ssf:stream-verify:", ["stream-updated"] = "ssf:stream-updated:"}
local function ctl_key(kind, sid) return P .. ctl_prefix[kind] .. sid end
local streams_key = P .. "ssf:streams"
local due_key = P .. "ssf:due"
local expiry_key = P .. "ssf:expiry"
local function sync_head(sid)
	local head = redis.call("ZRANGE", sdue_key(sid), 0, 0, "WITHSCORES")
	if head[1] then
		redis.call("ZADD", due_key, head[2], sid)
	else
		redis.call("ZREM", due_key, sid)
	end
end
local function sync_queues(jti, sid, delivery, held, next)
	if delivery == "push" and held == "0" then
		redis.call("ZADD", sdue_key(sid), next, jti)
	else
		redis.call("ZREM", sdue_key(sid), jti)
	end
	if delivery == "poll" and held == "0" then
		redis.call("ZADD", ready_key(sid), 0, jti)
	else
		redis.call("ZREM", ready_key(sid), jti)
	end
	sync_head(sid)
end
local function remove_event(jti)
	local f = redis.call("HMGET", ev_key(jti), "stream", "kind")
	if not f[1] then return 0 end
	redis.call("DEL", ev_key(jti))
	redis.call("ZREM", sdue_key(f[1]), jti)
	redis.call("ZREM", ready_key(f[1]), jti)
	redis.call("ZREM", expiry_key, jti)
	redis.call("SREM", idx_key(f[1]), jti)
	sync_head(f[1])
	if ctl_prefix[f[2]] and redis.call("GET", ctl_key(f[2], f[1])) == jti then
		redis.call("DEL", ctl_key(f[2], f[1]))
	end
	return 1
end
local function put_event(jti, sid, kind, delivery, held, claims, attempts, next, expires)
	if ctl_prefix[kind] then
		local old = redis.call("GET", ctl_key(kind, sid))
		if old then remove_event(old) end
		redis.call("SET", ctl_key(kind, sid), jti)
	end
	redis.call("HSET", ev_key(jti), "stream", sid, "kind", kind, "delivery", delivery,
		"held", held, "claims", claims, "attempts", attempts, "next", next, "expires", expires)
	redis.call("SADD", idx_key(sid), jti)
	redis.call("ZADD", expiry_key, expires, jti)
	sync_queues(jti, sid, delivery, held, next)
end
local function read_event(jti)
	local v = redis.call("HMGET", ev_key(jti), "stream", "kind", "delivery", "held", "claims", "attempts", "next", "expires")
	return {jti, v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]}
end
`

// ssfEnqueueLua: ARGV[2..10] = jti, stream, kind, delivery, held, claims,
// attempts, next, expires. Returns 0 when the JTI is already queued and 2
// when the event does not match its stream's current state.
const ssfEnqueueLua = ssfLuaPrelude + `
local jti, sid, kind, delivery, held = ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6]
if redis.call("EXISTS", ev_key(jti)) == 1 then return 0 end
local rec = redis.call("HGET", streams_key, sid)
if rec then
	local st = cjson.decode(rec)
	if st["delivery_method"] ~= delivery then return 2 end
	if kind == "event" then
		local want = "0"
		if st["status"] == "paused" then want = "1" end
		if st["status"] == "disabled" or held ~= want then return 2 end
	end
end
put_event(jti, sid, kind, delivery, held, ARGV[7], ARGV[8], ARGV[9], ARGV[10])
return 1
`

// ssfClaimDueLua: ARGV[2] = now, ARGV[3] = n, ARGV[4] = per-stream cap,
// ARGV[5] = now+lease. It visits the streams whose earliest due event is
// earliest, at most n of them, and leases up to the cap from each.
// Selecting and re-scoring happen in this one script, which is what makes
// ClaimDue single-winner across replicas.
const ssfClaimDueLua = ssfLuaPrelude + `
local n, per = tonumber(ARGV[3]), tonumber(ARGV[4])
local out = {}
for _, sid in ipairs(redis.call("ZRANGEBYSCORE", due_key, "-inf", ARGV[2], "LIMIT", 0, n)) do
	local sdue = sdue_key(sid)
	for _, jti in ipairs(redis.call("ZRANGEBYSCORE", sdue, "-inf", ARGV[2], "LIMIT", 0, math.min(per, n - #out))) do
		if redis.call("EXISTS", ev_key(jti)) == 1 then
			redis.call("ZADD", sdue, ARGV[5], jti)
			redis.call("HSET", ev_key(jti), "next", ARGV[5])
			out[#out + 1] = read_event(jti)
		else
			redis.call("ZREM", sdue, jti)
		end
	end
	sync_head(sid)
	if #out == n then break end
end
return out
`

// ssfRescheduleLua: ARGV[2..4] = jti, next, attempts. Returns 0 when the
// event is not queued.
const ssfRescheduleLua = ssfLuaPrelude + `
local jti = ARGV[2]
local f = redis.call("HMGET", ev_key(jti), "stream", "delivery", "held")
if not f[1] then return 0 end
redis.call("HSET", ev_key(jti), "next", ARGV[3], "attempts", ARGV[4])
sync_queues(jti, f[1], f[2], f[3], ARGV[3])
return 1
`

// ssfAckLua: ARGV[2] = stream ID, ARGV[3..] = JTIs.
const ssfAckLua = ssfLuaPrelude + `
for i = 3, #ARGV do
	if redis.call("HGET", ev_key(ARGV[i]), "stream") == ARGV[2] then
		remove_event(ARGV[i])
	end
end
return 1
`

// ssfPendingLua: ARGV[2] = stream ID, ARGV[3] = n. Returns the more flag
// followed by up to n events, lowest JTI first; it reads one entry past n
// from the stream's ready set and nothing else of its queue.
const ssfPendingLua = ssfLuaPrelude + `
local n = tonumber(ARGV[3])
local out = {0}
local jtis = redis.call("ZRANGE", ready_key(ARGV[2]), 0, n)
for i, jti in ipairs(jtis) do
	if i > n then
		out[1] = 1
	else
		out[#out + 1] = read_event(jti)
	end
end
return out
`

// ssfDeleteExpiredLua: ARGV[2] = now, ARGV[3] = batch size. Returns how
// many events it removed and how many expiry entries it consumed.
const ssfDeleteExpiredLua = ssfLuaPrelude + `
local removed = 0
local jtis = redis.call("ZRANGEBYSCORE", expiry_key, "-inf", ARGV[2], "LIMIT", 0, tonumber(ARGV[3]))
for _, jti in ipairs(jtis) do
	if remove_event(jti) == 1 then
		removed = removed + 1
	else
		redis.call("ZREM", expiry_key, jti)
	end
end
return {removed, #jtis}
`

// ssfStreamCreateLua: KEYS = streams, stream-clients; ARGV[1..3] = stream
// ID, client ID, record. Returns 0 when either identifier is taken.
const ssfStreamCreateLua = `
if redis.call("HEXISTS", KEYS[1], ARGV[1]) == 1 or redis.call("HEXISTS", KEYS[2], ARGV[2]) == 1 then
	return 0
end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[3])
redis.call("HSET", KEYS[2], ARGV[2], ARGV[1])
return 1
`

// ssfStreamUpdateLua: ARGV[2..5] = stream ID, record, delivery method,
// status; ARGV[6] = "1" when a stream-updated notice follows in
// ARGV[7..15] (jti, stream, kind, delivery, held, claims, attempts, next,
// expires). It rewrites the stream, moves its queued events to the new
// state and stores the notice. Returns 0 when the stream is missing and 2
// when the notice JTI is already queued, both before any write.
const ssfStreamUpdateLua = ssfLuaPrelude + `
local sid, delivery, status = ARGV[2], ARGV[4], ARGV[5]
if redis.call("HEXISTS", streams_key, sid) == 0 then return 0 end
if ARGV[6] == "1" and redis.call("EXISTS", ev_key(ARGV[7])) == 1 then return 2 end
redis.call("HSET", streams_key, sid, ARGV[3])
for _, jti in ipairs(redis.call("SMEMBERS", idx_key(sid))) do
	local f = redis.call("HMGET", ev_key(jti), "kind", "next")
	if f[1] == "event" and status == "disabled" then
		remove_event(jti)
	elseif f[1] then
		local held = "0"
		if f[1] == "event" and status == "paused" then held = "1" end
		redis.call("HSET", ev_key(jti), "delivery", delivery, "held", held)
		sync_queues(jti, sid, delivery, held, f[2])
	end
end
if ARGV[6] == "1" then
	put_event(ARGV[7], ARGV[8], ARGV[9], ARGV[10], ARGV[11], ARGV[12], ARGV[13], ARGV[14], ARGV[15])
end
return 1
`

// ssfStreamDeleteLua: KEYS = streams, stream-clients; ARGV[2] = stream
// ID. Drops the stream, its client slot and every queued event.
const ssfStreamDeleteLua = ssfLuaPrelude + `
local sid = ARGV[2]
local rec = redis.call("HGET", KEYS[1], sid)
if not rec then return 0 end
local cid = cjson.decode(rec)["client_id"]
redis.call("HDEL", KEYS[1], sid)
if redis.call("HGET", KEYS[2], cid) == sid then redis.call("HDEL", KEYS[2], cid) end
for _, jti in ipairs(redis.call("SMEMBERS", idx_key(sid))) do
	remove_event(jti)
end
redis.call("DEL", idx_key(sid), sdue_key(sid), ready_key(sid), ctl_key("verification", sid), ctl_key("stream-updated", sid))
redis.call("ZREM", due_key, sid)
return 1
`

type ssfScripts struct {
	enqueue, claimDue, reschedule, ack, pending, deleteExpired *redis.Script
	streamCreate, streamUpdate, streamDelete                   *redis.Script
}

func newSSFScripts() *ssfScripts {
	return &ssfScripts{
		enqueue:       redis.NewScript(ssfEnqueueLua),
		claimDue:      redis.NewScript(ssfClaimDueLua),
		reschedule:    redis.NewScript(ssfRescheduleLua),
		ack:           redis.NewScript(ssfAckLua),
		pending:       redis.NewScript(ssfPendingLua),
		deleteExpired: redis.NewScript(ssfDeleteExpiredLua),
		streamCreate:  redis.NewScript(ssfStreamCreateLua),
		streamUpdate:  redis.NewScript(ssfStreamUpdateLua),
		streamDelete:  redis.NewScript(ssfStreamDeleteLua),
	}
}

// ssfStreamStore implements [store.SSFStreamStore].
type ssfStreamStore struct {
	parent  *Store
	scripts *ssfScripts
}

// ssfEventStore implements [store.SSFEventStore].
type ssfEventStore struct {
	parent  *Store
	scripts *ssfScripts
}

func (s *Store) ssfStreamsKey() string       { return s.prefix + "ssf:streams" }
func (s *Store) ssfStreamClientsKey() string { return s.prefix + "ssf:stream-clients" }

// ssfStreamRecord is the JSON shape of a stored stream.
type ssfStreamRecord struct {
	ID                        string    `json:"id"`
	ClientID                  string    `json:"client_id"`
	DeliveryMethod            string    `json:"delivery_method"`
	EndpointURL               string    `json:"endpoint_url,omitempty"`
	SealedAuthorizationHeader []byte    `json:"sealed_authorization_header,omitempty"`
	EventsRequested           []string  `json:"events_requested,omitempty"`
	EventsDelivered           []string  `json:"events_delivered,omitempty"`
	Description               string    `json:"description,omitempty"`
	Status                    string    `json:"status"`
	StatusReason              string    `json:"status_reason,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

func (s *ssfStreamStore) encode(in *store.SSFStream) (string, error) {
	if in == nil {
		return "", errors.New("oidcredis: nil ssf stream")
	}
	payload, err := json.Marshal(ssfStreamRecord{
		ID:                        in.ID,
		ClientID:                  in.ClientID,
		DeliveryMethod:            string(in.Delivery.Method),
		EndpointURL:               in.Delivery.EndpointURL,
		SealedAuthorizationHeader: in.Delivery.SealedAuthorizationHeader,
		EventsRequested:           in.EventsRequested,
		EventsDelivered:           in.EventsDelivered,
		Description:               in.Description,
		Status:                    string(in.Status),
		StatusReason:              in.StatusReason,
		CreatedAt:                 in.CreatedAt,
		UpdatedAt:                 in.UpdatedAt,
	})
	if err != nil {
		return "", fmt.Errorf("oidcredis: marshal ssf stream: %w", err)
	}
	if err := s.parent.checkPayloadSize("ssf stream", payload); err != nil {
		return "", err
	}
	return string(payload), nil
}

func decodeSSFStream(raw string) (*store.SSFStream, error) {
	var rec ssfStreamRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, fmt.Errorf("oidcredis: unmarshal ssf stream: %w", err)
	}
	return &store.SSFStream{
		ID:       rec.ID,
		ClientID: rec.ClientID,
		Delivery: store.SSFDelivery{
			Method:                    store.SSFDeliveryMethod(rec.DeliveryMethod),
			EndpointURL:               rec.EndpointURL,
			SealedAuthorizationHeader: rec.SealedAuthorizationHeader,
		},
		EventsRequested: rec.EventsRequested,
		EventsDelivered: rec.EventsDelivered,
		Description:     rec.Description,
		Status:          store.SSFStreamStatus(rec.Status),
		StatusReason:    rec.StatusReason,
		CreatedAt:       rec.CreatedAt,
		UpdatedAt:       rec.UpdatedAt,
	}, nil
}

func (s *ssfStreamStore) Create(ctx context.Context, in *store.SSFStream) error {
	payload, err := s.encode(in)
	if err != nil {
		return err
	}
	created, err := s.scripts.streamCreate.Run(ctx, s.parent.client,
		[]string{s.parent.ssfStreamsKey(), s.parent.ssfStreamClientsKey()},
		in.ID, in.ClientID, payload,
	).Int()
	if err != nil {
		return fmt.Errorf("oidcredis: create ssf stream: %w", err)
	}
	if created == 0 {
		return store.ErrConflict
	}
	return nil
}

func (s *ssfStreamStore) Get(ctx context.Context, id string) (*store.SSFStream, error) {
	raw, err := s.parent.client.HGet(ctx, s.parent.ssfStreamsKey(), id).Result()
	if errors.Is(err, redis.Nil) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("oidcredis: HGET ssf stream: %w", err)
	}
	return decodeSSFStream(raw)
}

func (s *ssfStreamStore) GetByClient(ctx context.Context, clientID string) (*store.SSFStream, error) {
	id, err := s.parent.client.HGet(ctx, s.parent.ssfStreamClientsKey(), clientID).Result()
	if errors.Is(err, redis.Nil) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("oidcredis: HGET ssf stream client: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *ssfStreamStore) ListActive(ctx context.Context) ([]*store.SSFStream, error) {
	raws, err := s.parent.client.HVals(ctx, s.parent.ssfStreamsKey()).Result()
	if err != nil {
		return nil, fmt.Errorf("oidcredis: HVALS ssf streams: %w", err)
	}
	out := make([]*store.SSFStream, 0, len(raws))
	for _, raw := range raws {
		st, err := decodeSSFStream(raw)
		if err != nil {
			return nil, err
		}
		if st.Status == store.SSFStreamEnabled || st.Status == store.SSFStreamPaused {
			out = append(out, st)
		}
	}
	return out, nil
}

// Update replaces the record but keeps the client the stream was created
// for: the client index maps client ID to stream ID and is never rewritten.
func (s *ssfStreamStore) Update(ctx context.Context, in *store.SSFStream, notice *store.SSFEvent) error {
	if in == nil {
		return errors.New("oidcredis: nil ssf stream")
	}
	cur, err := s.Get(ctx, in.ID)
	if err != nil {
		return err
	}
	keep := *in
	keep.ClientID = cur.ClientID
	payload, err := s.encode(&keep)
	if err != nil {
		return err
	}
	args := []any{s.parent.prefix, in.ID, payload, string(in.Delivery.Method), string(in.Status), ssfFlag(notice != nil)}
	if notice != nil {
		if err := s.parent.checkPayloadSize("ssf event", notice.Claims); err != nil {
			return err
		}
		args = append(args, ssfEventArgs(notice)...)
	}
	updated, err := s.scripts.streamUpdate.Run(ctx, s.parent.client, nil, args...).Int()
	if err != nil {
		return fmt.Errorf("oidcredis: update ssf stream: %w", err)
	}
	switch updated {
	case 0:
		return store.ErrNotFound
	case 2:
		return store.ErrAlreadyExists
	}
	return nil
}

func (s *ssfStreamStore) Delete(ctx context.Context, id string) error {
	deleted, err := s.scripts.streamDelete.Run(ctx, s.parent.client,
		[]string{s.parent.ssfStreamsKey(), s.parent.ssfStreamClientsKey()},
		s.parent.prefix, id,
	).Int()
	if err != nil {
		return fmt.Errorf("oidcredis: delete ssf stream: %w", err)
	}
	if deleted == 0 {
		return store.ErrNotFound
	}
	return nil
}

func ssfMicros(t time.Time) string { return strconv.FormatInt(t.UnixMicro(), 10) }

func ssfFlag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (e *ssfEventStore) Enqueue(ctx context.Context, ev *store.SSFEvent) error {
	if ev == nil {
		return errors.New("oidcredis: nil ssf event")
	}
	if err := e.parent.checkPayloadSize("ssf event", ev.Claims); err != nil {
		return err
	}
	args := append([]any{e.parent.prefix}, ssfEventArgs(ev)...)
	recorded, err := e.scripts.enqueue.Run(ctx, e.parent.client, nil, args...).Int()
	if err != nil {
		return fmt.Errorf("oidcredis: enqueue ssf event: %w", err)
	}
	switch recorded {
	case 0:
		return store.ErrAlreadyExists
	case 2:
		return store.ErrConflict
	}
	return nil
}

// ssfEventArgs is the event the scripts read after the prefix: jti,
// stream, kind, delivery, held, claims, attempts, next and expires.
func ssfEventArgs(ev *store.SSFEvent) []any {
	return []any{
		ev.JTI, ev.StreamID, string(ev.Kind), string(ev.Delivery),
		ssfFlag(ev.Held), ev.Claims, strconv.Itoa(ev.Attempts),
		ssfMicros(ev.NextAttemptAt), ssfMicros(ev.ExpiresAt),
	}
}

func (e *ssfEventStore) ClaimDue(ctx context.Context, now time.Time, n, perStream int, lease time.Duration) ([]*store.SSFEvent, error) {
	if n <= 0 || perStream <= 0 {
		return nil, errors.New("oidcredis: ssf claim sizes must be positive")
	}
	res, err := e.scripts.claimDue.Run(ctx, e.parent.client, nil,
		e.parent.prefix, ssfMicros(now), n, perStream, ssfMicros(now.Add(lease)),
	).Slice()
	if err != nil {
		return nil, fmt.Errorf("oidcredis: claim ssf events: %w", err)
	}
	return decodeSSFEvents(res)
}

func (e *ssfEventStore) Reschedule(ctx context.Context, jti string, next time.Time, attempts int) error {
	updated, err := e.scripts.reschedule.Run(ctx, e.parent.client, nil,
		e.parent.prefix, jti, ssfMicros(next), strconv.Itoa(attempts),
	).Int()
	if err != nil {
		return fmt.Errorf("oidcredis: reschedule ssf event: %w", err)
	}
	if updated == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (e *ssfEventStore) Ack(ctx context.Context, streamID string, jtis []string) error {
	if len(jtis) == 0 {
		return nil
	}
	args := make([]any, 0, len(jtis)+2)
	args = append(args, e.parent.prefix, streamID)
	for _, jti := range jtis {
		args = append(args, jti)
	}
	if err := e.scripts.ack.Run(ctx, e.parent.client, nil, args...).Err(); err != nil {
		return fmt.Errorf("oidcredis: ack ssf events: %w", err)
	}
	return nil
}

func (e *ssfEventStore) Pending(ctx context.Context, streamID string, n int) ([]*store.SSFEvent, bool, error) {
	if n <= 0 {
		return nil, false, errors.New("oidcredis: ssf pending size must be positive")
	}
	res, err := e.scripts.pending.Run(ctx, e.parent.client, nil,
		e.parent.prefix, streamID, n,
	).Slice()
	if err != nil {
		return nil, false, fmt.Errorf("oidcredis: pending ssf events: %w", err)
	}
	if len(res) == 0 {
		return nil, false, errors.New("oidcredis: pending ssf events: empty script reply")
	}
	more, ok := res[0].(int64)
	if !ok {
		return nil, false, fmt.Errorf("oidcredis: pending ssf events: more flag %T", res[0])
	}
	events, err := decodeSSFEvents(res[1:])
	if err != nil {
		return nil, false, err
	}
	return events, more == 1, nil
}

func (e *ssfEventStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	total := 0
	for {
		res, err := e.scripts.deleteExpired.Run(ctx, e.parent.client, nil,
			e.parent.prefix, ssfMicros(now), ssfDeleteExpiredBatch,
		).Int64Slice()
		if err != nil {
			return total, fmt.Errorf("oidcredis: delete expired ssf events: %w", err)
		}
		if len(res) != 2 {
			return total, errors.New("oidcredis: delete expired ssf events: malformed script reply")
		}
		total += int(res[0])
		if res[1] < ssfDeleteExpiredBatch {
			return total, nil
		}
	}
}

// decodeSSFEvents parses the rows read_event builds: jti, stream, kind,
// delivery, held, claims, attempts, next, expires.
func decodeSSFEvents(rows []any) ([]*store.SSFEvent, error) {
	out := make([]*store.SSFEvent, 0, len(rows))
	for _, row := range rows {
		cols, ok := row.([]any)
		if !ok || len(cols) != 9 {
			return nil, errors.New("oidcredis: malformed ssf event row")
		}
		f := make([]string, len(cols))
		for i, c := range cols {
			if f[i], ok = c.(string); !ok {
				return nil, fmt.Errorf("oidcredis: ssf event field %d is %T", i, c)
			}
		}
		attempts, err := strconv.Atoi(f[6])
		if err != nil {
			return nil, fmt.Errorf("oidcredis: ssf event attempts: %w", err)
		}
		next, err := strconv.ParseInt(f[7], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("oidcredis: ssf event next attempt: %w", err)
		}
		expires, err := strconv.ParseInt(f[8], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("oidcredis: ssf event expiry: %w", err)
		}
		out = append(out, &store.SSFEvent{
			JTI:           f[0],
			StreamID:      f[1],
			Kind:          store.SSFEventKind(f[2]),
			Delivery:      store.SSFDeliveryMethod(f[3]),
			Held:          f[4] == "1",
			Claims:        []byte(f[5]),
			Attempts:      attempts,
			NextAttemptAt: time.UnixMicro(next).UTC(),
			ExpiresAt:     time.UnixMicro(expires).UTC(),
		})
	}
	return out, nil
}

var (
	_ store.SharedSignalsStore = (*Store)(nil)
	_ store.SSFStreamStore     = (*ssfStreamStore)(nil)
	_ store.SSFEventStore      = (*ssfEventStore)(nil)
)
