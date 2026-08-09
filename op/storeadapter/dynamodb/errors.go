package oidcdynamo

import (
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// conditionalCheckFailed is the code DynamoDB reports for an action a
// ConditionExpression turned away, both as a standalone exception and
// as one entry of a transaction's cancellation reasons.
const conditionalCheckFailed = "ConditionalCheckFailed"

// ErrInvalidDocument is returned when a record cannot be encoded to, or
// decoded from, the JSON document attribute. An encode failure means
// the embedder supplied a value JSON cannot represent (NaN, a function,
// a cycle); a decode failure means the stored item was written by
// something other than this adapter.
var ErrInvalidDocument = errors.New("oidcdynamo: record is not a valid stored document")

// ErrTransactionTooLarge is returned by Commit when a transaction
// accumulated more writes than DynamoDB's TransactWriteItems accepts.
// The adapter reports it with the offending count rather than letting
// the service return an opaque ValidationException.
var ErrTransactionTooLarge = errors.New("oidcdynamo: transaction exceeds the TransactWriteItems item limit")

// maxTransactionItems is the ceiling TransactWriteItems enforces.
const maxTransactionItems = 100

// wrapErr decorates a service error with the substore operation that
// issued it. Callers MUST map "not found" and conditional-check
// failures before reaching this helper.
func wrapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("oidcdynamo: %s: %w", op, err)
}

// isConditionalCheckFailed reports whether err is DynamoDB's rejection
// of a ConditionExpression. It is the adapter's single concurrency
// signal: every single-use consumption and every compare-and-swap
// distinguishes "lost the race" from "backend fault" through it.
func isConditionalCheckFailed(err error) bool {
	var cond *types.ConditionalCheckFailedException
	return errors.As(err, &cond)
}

// isTransactionCanceledByCondition reports whether a TransactWriteItems
// failure was caused by one of its condition expressions rather than by
// throughput, a validation error, or a conflicting concurrent
// transaction. DynamoDB reports every cancellation through one
// exception carrying a per-action reason list, so the reasons have to
// be inspected to tell a lost race from a real fault.
func isTransactionCanceledByCondition(err error) bool {
	return slices.Contains(transactionCancellationCodes(err), conditionalCheckFailed)
}

// transactionCancellationCodes returns the cancellation code of every
// action of a failed TransactWriteItems, in the order the actions were
// submitted, or nil when err is not a cancellation. It is how a
// multi-action write tells which of its guards rejected it; an action
// that was not itself at fault reports "None".
func transactionCancellationCodes(err error) []string {
	var canceled *types.TransactionCanceledException
	if !errors.As(err, &canceled) {
		return nil
	}
	codes := make([]string, len(canceled.CancellationReasons))
	for i, reason := range canceled.CancellationReasons {
		if reason.Code != nil {
			codes[i] = *reason.Code
		}
	}
	return codes
}
