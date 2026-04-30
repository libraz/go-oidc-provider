package scenarios_test

// Catalog: test/scenarios/catalog/client_auth.yaml (CA-<sub>-NNN)
// Spec:
//   - RFC 6749 §2.3, §5.2 — Client Authentication
//   - RFC 6749 Appendix B — application/x-www-form-urlencoded encoding
//   - RFC 7521 — Assertion Framework
//   - RFC 7523 — JWT Profile for Client Authentication
//   - RFC 8705 §2 — OAuth 2.0 Mutual-TLS Client Authentication
//   - RFC 7591 — Dynamic Client Registration
//   - OIDC Core 1.0 §9 — Client Authentication
//   - draft-ietf-oauth-attestation-based-client-auth

import "testing"

func TestScenario_CA_COMMON_01_NoMechanismProvidedRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-COMMON-01")
}

func TestScenario_CA_COMMON_02_UnknownClientIDRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-COMMON-02")
}

func TestScenario_CA_COMMON_03_DoubleMechanismRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-COMMON-03")
}

func TestScenario_CA_COMMON_04_RegisteredMethodMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-COMMON-04")
}

func TestScenario_CA_COMMON_05_BodyClientIDMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-COMMON-05")
}

func TestScenario_CA_COMMON_06_BasicChallengeOnlyOnBasicFailure(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-COMMON-06")
}

func TestScenario_CA_COMMON_07_ErrorResponsePreservesNoStore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-COMMON-07")
}

func TestScenario_CA_NONE_01_NoneClientAuthenticatesByClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-NONE-01")
}

func TestScenario_CA_NONE_02_NoneClientWithSecretRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-NONE-02")
}

func TestScenario_CA_NONE_03_NoneClientNotAllowedForConfidentialFlows(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-NONE-03")
}

func TestScenario_CA_BASIC_01_WellFormedBasicHeaderAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-01")
}

func TestScenario_CA_BASIC_02_BasicWithMatchingBodyClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-02")
}

func TestScenario_CA_BASIC_03_BasicAcceptedForPostRegisteredClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-03")
}

func TestScenario_CA_BASIC_04_AppendixBFormURLEncoding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-04")
}

func TestScenario_CA_BASIC_05_BasicHeaderBodyClientIDMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-05")
}

func TestScenario_CA_BASIC_06_ImproperlyEncodedBasicHeader(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-06")
}

func TestScenario_CA_BASIC_07_NonBasicSchemeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-07")
}

func TestScenario_CA_BASIC_08_EmptySecretInBasicRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-08")
}

func TestScenario_CA_BASIC_09_BasicSecretMismatchInvalidClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-09")
}

func TestScenario_CA_BASIC_10_BasicSecretExpired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-BASIC-10")
}

func TestScenario_CA_POST_01_FormBodyCredentialsAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-POST-01")
}

func TestScenario_CA_POST_02_ChunkedTransferEncodingAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-POST-02")
}

func TestScenario_CA_POST_03_PostSecretMismatchInvalidClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-POST-03")
}

func TestScenario_CA_POST_04_EmptyPostSecretMethodMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-POST-04")
}

func TestScenario_CA_POST_05_PostSecretExpired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-POST-05")
}

func TestScenario_CA_POST_06_PostFromBasicRegisteredClientStrictReject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-POST-06")
}

func TestScenario_CA_CSJWT_01_AssertionTypeRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-01")
}

func TestScenario_CA_CSJWT_02_AssertionTypeWrongValueRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-02")
}

func TestScenario_CA_CSJWT_03_MissingOrMalformedAssertionRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-03")
}

func TestScenario_CA_CSJWT_04_HMACSignedWithClientSecret(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-04")
}

func TestScenario_CA_CSJWT_05_RequiredClaimsEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-05")
}

func TestScenario_CA_CSJWT_06_IssMustEqualClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-06")
}

func TestScenario_CA_CSJWT_07_SubMustEqualClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-07")
}

func TestScenario_CA_CSJWT_08_AudAcceptanceForms(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-08")
}

func TestScenario_CA_CSJWT_09_JtiSingleUseEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-09")
}

func TestScenario_CA_CSJWT_10_ExpiredAssertionRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-10")
}

func TestScenario_CA_CSJWT_11_ClockToleranceDefaultZero(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-11")
}

func TestScenario_CA_CSJWT_12_BodyClientIDMismatchAssertion(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-12")
}

func TestScenario_CA_CSJWT_13_AssertionWithBasicHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-13")
}

func TestScenario_CA_CSJWT_14_RegisteredAlgMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-14")
}

func TestScenario_CA_CSJWT_15_DiscoveryAlgRestrictionEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-15")
}

func TestScenario_CA_CSJWT_16_ClientSecretExpiredForAssertion(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-16")
}

func TestScenario_CA_CSJWT_17_NoneRegisteredCannotUseAssertion(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-17")
}

func TestScenario_CA_CSJWT_18_HSResponseAlgRequiresSecret(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-CSJWT-18")
}

func TestScenario_CA_PKJWT_01_AsymmetricAlgsAcceptedHSRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-01")
}

func TestScenario_CA_PKJWT_02_RequiredClaimsEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-02")
}

func TestScenario_CA_PKJWT_03_IssEqualsSubEqualsClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-03")
}

func TestScenario_CA_PKJWT_04_AudAcceptanceForms(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-04")
}

func TestScenario_CA_PKJWT_05_KeyResolvedFromJWKSWithRefetch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-05")
}

func TestScenario_CA_PKJWT_06_NoMatchingKidRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-06")
}

func TestScenario_CA_PKJWT_07_JtiSingleUseEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-07")
}

func TestScenario_CA_PKJWT_08_ClockToleranceDefaultZero(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-08")
}

func TestScenario_CA_PKJWT_09_RegisteredAlgPinning(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-09")
}

func TestScenario_CA_PKJWT_10_DiscoveryAlgRestrictionEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-10")
}

func TestScenario_CA_PKJWT_11_OctKeyRejectedForPrivateKeyJWT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-PKJWT-11")
}

func TestScenario_CA_MTLS_PKI_01_ProxyCertificateAuthorisedAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-01")
}

func TestScenario_CA_MTLS_PKI_02_ExactlyOneSubjectMetadataAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-02")
}

func TestScenario_CA_MTLS_PKI_03_RegisteredSubjectExactMatchRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-03")
}

func TestScenario_CA_MTLS_PKI_04_NoCertificateForwardedRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-04")
}

func TestScenario_CA_MTLS_PKI_05_ProxyVerifyFailureRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-05")
}

func TestScenario_CA_MTLS_PKI_06_SubjectDNCanonicalised(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-06")
}

func TestScenario_CA_MTLS_PKI_07_SANDNSCaseAndIDNRules(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-07")
}

func TestScenario_CA_MTLS_PKI_08_SANURIExactMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-08")
}

func TestScenario_CA_MTLS_PKI_09_SANIPNormalisation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-09")
}

func TestScenario_CA_MTLS_PKI_10_SANEmailRFC822CaseRules(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-10")
}

func TestScenario_CA_MTLS_PKI_11_EmbedderCertificateHooksDelegated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-11")
}

func TestScenario_CA_MTLS_PKI_12_DiscoveryAdvertisesMTLSAliases(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-PKI-12")
}

func TestScenario_CA_MTLS_SS_01_ThumbprintMatchesRegisteredJWK(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-SS-01")
}

func TestScenario_CA_MTLS_SS_02_StaleJWKSURIRefetched(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-SS-02")
}

func TestScenario_CA_MTLS_SS_03_RSAECEd25519CertificatesAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-SS-03")
}

func TestScenario_CA_MTLS_SS_04_NoMatchingThumbprintRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-SS-04")
}

func TestScenario_CA_MTLS_SS_05_NoCertificateAvailableRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-SS-05")
}

func TestScenario_CA_MTLS_SS_06_TLSSubjectMetadataNotAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-MTLS-SS-06")
}

func TestScenario_CA_ATT_01_BothAttestationAndPoPHeadersRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-01")
}

func TestScenario_CA_ATT_02_AttestationTypHeadersEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-02")
}

func TestScenario_CA_ATT_03_AttestationRequiredClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-03")
}

func TestScenario_CA_ATT_04_PoPRequiredClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-04")
}

func TestScenario_CA_ATT_05_PoPAudArrayShapeAndIssuer(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-05")
}

func TestScenario_CA_ATT_06_ChallengeEndpointEmitsHMACToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-06")
}

func TestScenario_CA_ATT_07_MissingChallengeReturnsUseAttestationChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-07")
}

func TestScenario_CA_ATT_08_PoPJtiSingleUseEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-08")
}

func TestScenario_CA_ATT_09_AttesterKeyHookDelegated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-09")
}

func TestScenario_CA_ATT_10_AttestationPolicyHookDelegated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-10")
}

func TestScenario_CA_ATT_11_CnfJwkBindsAttestationToPoP(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ATT-11")
}

func TestScenario_CA_DISC_01_OnlyEnabledMethodsAdvertised(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-DISC-01")
}

func TestScenario_CA_DISC_02_SigningAlgValuesPublishedConditionally(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-DISC-02")
}

func TestScenario_CA_DISC_03_ClientSecretJWTPublishesHMACOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-DISC-03")
}

func TestScenario_CA_DISC_04_PrivateKeyJWTPublishesAsymmetricOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-DISC-04")
}

func TestScenario_CA_DISC_05_BothJWTMethodsPublishUnion(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-DISC-05")
}

func TestScenario_CA_DISC_06_RevocationIntrospectionMethodsParity(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-DISC-06")
}

func TestScenario_CA_DISC_07_MTLSEndpointAliasesGated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-DISC-07")
}

func TestScenario_CA_ERR_01_InvalidClient401WithConditionalChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ERR-01")
}

func TestScenario_CA_ERR_02_ErrorDescriptionDoesNotLeakDetail(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ERR-02")
}

func TestScenario_CA_ERR_03_TimingEqualisedAcrossFailurePaths(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ERR-03")
}

func TestScenario_CA_ERR_04_AuthFlowRateLimitOPScoped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ERR-04")
}

func TestScenario_CA_ERR_05_ClientAuthnFailureAuditEvent(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CA-ERR-05")
}
