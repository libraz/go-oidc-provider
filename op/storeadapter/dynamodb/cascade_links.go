package oidcdynamo

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// attrLinkSort is the sort key of the cascade-links table: the primary
// key of the linked item.
const attrLinkSort = "sk"

// A cascade that must visit every committed item of a parent — every
// token of a grant or client, every grant of a subject or client — cannot
// rely on a secondary index, which is eventually consistent. Each such
// item is therefore written together with one link per parent attribute
// in the cascade-links table, partitioned by (table, attribute, value) so
// a strongly consistent Query lists exactly the members. The index query
// is still united in, which reaches items written before the links
// existed.

// linkPK names the link partition of items in table whose attr equals value.
func linkPK(table, attr, value string) string {
	return table + "#" + attr + "#" + value
}

// linkKey is the primary key of one link.
func linkKey(partition, member string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: avS(partition), attrLinkSort: avS(member)}
}

// linkItems renders the links of entry for each of attrs it carries. A
// link inherits the item's TTL so storage is reclaimed on the same
// schedule.
func linkItems(table string, entry item, attrs ...string) []item {
	member := readS(entry, attrPK)
	out := make([]item, 0, len(attrs))
	for _, attr := range attrs {
		value := readS(entry, attr)
		if value == "" {
			continue
		}
		link := newCompositeItem(linkPK(table, attr, value), attrLinkSort, avS(member))
		if ttl, ok := entry[attrTTL]; ok {
			link[attrTTL] = ttl
		}
		out = append(out, link)
	}
	return out
}

// putLinks writes links before the item they describe: a link that
// outlives a failed item write names nothing a cascade will act on,
// whereas an item committed without its link would be invisible to it.
func (s *Store) putLinks(ctx context.Context, links []item) error {
	for _, link := range links {
		if err := s.overwrite(ctx, s.names.cascadeLinks, link); err != nil {
			return err
		}
	}
	return nil
}

// stageLinks buffers the links so they commit with the item.
func (b *txBuffer) stageLinks(links []item) error {
	for _, link := range links {
		bufKey := readS(link, attrPK) + "\x00" + readS(link, attrLinkSort)
		if err := b.put(b.parent.names.cascadeLinks, bufKey, link); err != nil {
			return err
		}
	}
	return nil
}

// dropLinks removes the links of an item that is being deleted.
func (s *Store) dropLinks(ctx context.Context, links []item) error {
	for _, link := range links {
		if _, err := s.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(s.names.cascadeLinks),
			Key:       linkKey(readS(link, attrPK), readS(link, attrLinkSort)),
		}); err != nil {
			return err
		}
	}
	return nil
}

// stageDropLinks buffers the removal of links with the deletion of their item.
func (b *txBuffer) stageDropLinks(links []item) error {
	for _, link := range links {
		partition, member := readS(link, attrPK), readS(link, attrLinkSort)
		err := b.record(&txOp{
			kind:  txDelete,
			table: b.parent.names.cascadeLinks,
			pk:    partition + "\x00" + member,
			key:   linkKey(partition, member),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// enumerateCommitted returns the primary key of every item of table whose
// attr equals value, for operations that must visit each committed item —
// a revocation or deletion cascade. It unites a strongly consistent read
// of the item links with the index query (index), which covers items
// written before the links existed. Callers act on each key through a
// guarded write or a primary-key re-read, never on a hit as listed.
func (s *Store) enumerateCommitted(ctx context.Context, table, index, attr, value string) ([]string, error) {
	linked, err := s.queryPartition(ctx, s.names.cascadeLinks, linkPK(table, attr, value))
	if err != nil {
		return nil, err
	}
	indexed, err := s.queryIndex(ctx, table, index, attr, value)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(linked))
	keys := make([]string, 0, len(linked))
	add := func(pk string) {
		if _, dup := seen[pk]; dup || pk == "" {
			return
		}
		seen[pk] = struct{}{}
		keys = append(keys, pk)
	}
	for _, link := range linked {
		add(readS(link, attrLinkSort))
	}
	for _, pk := range itemKeys(indexed) {
		add(pk)
	}
	return keys, nil
}
